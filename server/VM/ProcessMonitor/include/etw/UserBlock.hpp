#pragma once
#include <krabs.hpp>
#include <cstddef>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "Deadline.hpp"

struct UserProviderEnableStats {
  std::size_t requested = 0;
  std::size_t resolved = 0;
  std::size_t unresolved = 0;
  std::size_t enabled = 0;
  std::size_t failed_enable = 0;
};

class UserBlock {
public:
  using Callback = std::function<void(const EVENT_RECORD &, const krabs::trace_context &)>;
  explicit UserBlock(const std::wstring &userSessionName);
  void start(Callback on_event);
  void stop();
  bool stopWithDeadline(const Deadline &deadline);

  void addApiCallsProvider(UCHAR level,
                           ULONGLONG any,
                           ULONGLONG all);
  bool addSysmonProvider(UCHAR level,
                         ULONGLONG any,
                         ULONGLONG all);
  void addAnalystProviders(UCHAR level,
                           ULONGLONG any,
                           ULONGLONG all);

  [[nodiscard]] UserProviderEnableStats getProviderEnableStats() const;

  void addProvider(const wchar_t *name,
                   UCHAR level,
                   ULONGLONG any,
                   ULONGLONG all);

  void addProvider(const GUID &id,
                   UCHAR level,
                   ULONGLONG any,
                   ULONGLONG all);

private:
  static bool s_tryParseGuidString(const wchar_t *s, GUID &out);
  static bool s_tryResolveProviderGuidByName(const wchar_t *name, GUID &out);
  bool _addProviderByName(const wchar_t *name,
                          UCHAR level,
                          ULONGLONG any,
                          ULONGLONG all);
  void _logMissingProviderOnce(const wchar_t *name);

private:
  std::unique_ptr<krabs::user_trace> m_trace;
  std::vector<std::pair<GUID, std::unique_ptr<krabs::provider<>>>> m_providers;
  std::unordered_set<std::wstring> m_loggedMissingProviders;
  UserProviderEnableStats m_providerStats{};
  std::wstring m_sessionName;
  std::thread m_thread;
  Callback m_cb;
};
