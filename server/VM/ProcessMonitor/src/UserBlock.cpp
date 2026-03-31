#include "UserBlock.hpp"

#include <new>
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <iostream>

#include "ProcessMonitorConstants.hpp"
#include "ProviderProfiles.hpp"
#include "UserBlockConstants.hpp"
#include "Utils.hpp"

UserBlock::UserBlock(const std::wstring &userSessionName)
    : m_sessionName(userSessionName) {}

bool UserBlock::s_tryParseGuidString(const wchar_t *s, GUID &out) {
  if (!s || !*s) {
    return false;
  }

  std::wstring t = s;
  t = Utils::trim(t);

  if (!t.empty() && t.front() != L'{') {
    t = L"{" + t + L"}";
  }

  return SUCCEEDED(CLSIDFromString(t.c_str(), &out));
}

bool UserBlock::s_tryResolveProviderGuidByName(const wchar_t *name, GUID &out) {
  if (!name || !*name) {
    return false;
  }

  ULONG size = 0;
  auto status = TdhEnumerateProviders(nullptr, &size);
  if (status != ERROR_INSUFFICIENT_BUFFER) {
    return false;
  }

  std::unique_ptr<BYTE[]> buf(new (std::nothrow) BYTE[size]);
  if (!buf) {
    return false;
  }

  auto info = reinterpret_cast<PROVIDER_ENUMERATION_INFO *>(buf.get());
  status = TdhEnumerateProviders(info, &size);
  if (status != ERROR_SUCCESS) {
    return false;
  }

  for (ULONG i = 0; i < info->NumberOfProviders; ++i) {
    auto const &pi = info->TraceProviderInfoArray[i];
    auto pname = reinterpret_cast<const wchar_t *>(
        reinterpret_cast<const BYTE *>(info) + pi.ProviderNameOffset);
    if (_wcsicmp(pname, name) == 0) {
      out = pi.ProviderGuid;

      return true;
    }
  }
  return false;
}

void UserBlock::addProvider(const wchar_t *name,
                            UCHAR level,
                            ULONGLONG any,
                            ULONGLONG all) {
  (void)_addProviderByName(name, level, any, all);
}

void UserBlock::addProvider(const GUID &id,
                            UCHAR level,
                            ULONGLONG any,
                            ULONGLONG all) {
  auto p = std::make_unique<krabs::provider<>>(id);
  p->level(level);
  if (any) {
    p->any(any);
  }

  if (all) {
    p->all(all);
  }
  m_providers.emplace_back(id, std::move(p));
}

void UserBlock::addApiCallsProvider(UCHAR level,
                                    ULONGLONG any,
                                    ULONGLONG all) {
  addAnalystProviders(level, any, all);
}

void UserBlock::addAnalystProviders(UCHAR level,
                                    ULONGLONG any,
                                    ULONGLONG all) {
  m_providers.clear();
  m_loggedMissingProviders.clear();
  m_providerStats = UserProviderEnableStats{};

  for (const auto *providerName : ProviderProfiles::getAnalystUserProviders()) {
    ++m_providerStats.requested;
    if (ProviderProfiles::isForbiddenProvider(providerName)) {
      ++m_providerStats.unresolved;
      _logMissingProviderOnce(providerName);
      continue;
    }

    if (_addProviderByName(providerName, level, any, all)) {
      ++m_providerStats.resolved;
      continue;
    }

    ++m_providerStats.unresolved;
    _logMissingProviderOnce(providerName);
  }
}

bool UserBlock::addSysmonProvider(UCHAR level,
                                  ULONGLONG any,
                                  ULONGLONG all) {
  ++m_providerStats.requested;
  if (_addProviderByName(ProcessMonitorConstants::SYSMON_PROVIDER_NAME.data(), level, any, all)) {
    ++m_providerStats.resolved;
    return true;
  }

  ++m_providerStats.unresolved;
  OutputDebugStringA(UserBlockConstants::SYSMON_UNAVAILABLE_MSG);
  return false;
}

UserProviderEnableStats UserBlock::getProviderEnableStats() const {
  return m_providerStats;
}

void UserBlock::start(Callback on_event) {
  stop();

  m_trace = std::make_unique<krabs::user_trace>(m_sessionName.c_str());

  m_cb = std::move(on_event);
  m_providerStats.enabled = 0;
  m_providerStats.failed_enable = 0;

  static std::atomic<std::size_t> s_logged{0};
  for (auto const &[providerId, providerPtr] : m_providers) {
    try {
      auto &p = *providerPtr;
      p.add_on_event_callback(m_cb);
      m_trace->enable(p);
      ++m_providerStats.enabled;

      if (s_logged.fetch_add(1, std::memory_order_relaxed) < UserBlockConstants::PROVIDER_ENABLE_LOG_LIMIT) {
        wchar_t buf[64]{};
        StringFromGUID2(providerId, buf, static_cast<int>(std::size(buf)));
        std::string msg = "UserBlock: enabled provider ";
        msg += Utils::narrow_utf8(buf);
        msg += "\n";
        OutputDebugStringA(msg.c_str());
      }
    } catch (const std::exception &e) {
      ++m_providerStats.failed_enable;
      std::string msg = std::string("UserBlock: enable failed: ") + e.what() + "\n";
      OutputDebugStringA(msg.c_str());
      wchar_t buf[64]{};
      StringFromGUID2(providerId, buf, static_cast<int>(std::size(buf)));
      std::wcout << L"UserBlock: enable failed for provider " << buf << L"\n";
    } catch (...) {
      ++m_providerStats.failed_enable;
      OutputDebugStringA("UserBlock: enable failed: unknown exception\n");
      std::wcout << L"UserBlock: enable failed: unknown exception\n";
    }
  }

  m_thread = std::thread([this] {
    try {
      m_trace->start();
    } catch (const std::exception &e) {
      std::string msg = std::string("UserBlock: trace start failed: ") + e.what() + "\n";
      OutputDebugStringA(msg.c_str());
    } catch (...) {
      OutputDebugStringA("UserBlock: trace start failed: unknown exception\n");
    }
  });
}

void UserBlock::stop() {
  if (m_trace) {
    m_trace->stop();
  }
  if (m_thread.joinable()) {
    m_thread.join();
  }
  m_trace.reset();
  m_cb = Callback{};
}

bool UserBlock::stopWithDeadline(const Deadline &deadline) {
  if (m_trace) {
    m_trace->stop();
  }

  bool ok = true;
  if (m_thread.joinable()) {
    const auto rem = deadline.remaining_ms();
    const DWORD waitMs = static_cast<DWORD>(std::clamp<long long>(rem.count(), UserBlockConstants::MIN_WAIT_MS, UserBlockConstants::MAX_WAIT_MS));
    const HANDLE h = reinterpret_cast<HANDLE>(m_thread.native_handle());
    const DWORD res = WaitForSingleObject(h, waitMs);
    if (res == WAIT_OBJECT_0) {
      m_thread.join();
    } else {
      OutputDebugStringA(UserBlockConstants::TIMEOUT_DETACH_MSG);
      m_thread.detach();
      ok = false;
    }
  }

  m_trace.reset();
  m_cb = Callback{};
  return ok;
}

bool UserBlock::_addProviderByName(const wchar_t *name,
                                   UCHAR level,
                                   ULONGLONG any,
                                   ULONGLONG all) {
  GUID gid{};
  if (s_tryParseGuidString(name, gid) || s_tryResolveProviderGuidByName(name, gid)) {
    addProvider(gid, level, any, all);
    return true;
  }
  return false;
}

void UserBlock::_logMissingProviderOnce(const wchar_t *name) {
  if (!name || !*name) {
    return;
  }
  std::wstring providerName{name};
  if (m_loggedMissingProviders.contains(providerName)) {
    return;
  }
  m_loggedMissingProviders.insert(providerName);

  std::string msg = "UserBlock: provider unavailable or not registered (continuing): ";
  msg += Utils::narrow_utf8(providerName);
  msg += "\n";
  OutputDebugStringA(msg.c_str());
}
