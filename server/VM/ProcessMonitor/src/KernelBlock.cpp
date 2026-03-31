#include "KernelBlock.hpp"
#include <stdexcept>
#include <windows.h>
#include <algorithm>
#include <string>
#include "KernelBlockConstants.hpp"

KernelBlock::KernelBlock(const std::wstring &userSessionName)
    : m_sessionName(userSessionName) {
}

void KernelBlock::addDefaultKernelProviders() {
  addProvider<krabs::kernel::process_provider>();
  addProvider<krabs::kernel::thread_provider>();
  addProvider<krabs::kernel::image_load_provider>();
  addProvider<krabs::kernel::registry_provider>();
  addProvider<krabs::kernel::file_io_provider>();
  addProvider<krabs::kernel::network_tcpip_provider>();
  addProvider<krabs::kernel::file_init_io_provider>();
  addProvider<krabs::kernel::disk_io_provider>();
  addProvider<krabs::kernel::disk_file_io_provider>();
  addProvider<krabs::kernel::context_switch_provider>();
}

void KernelBlock::start(const Callback &cb) {
  if (m_thread.joinable()) {
    throw std::runtime_error("KernelBlock::start called while already running");
  }

  m_cb = cb;
  m_trace = std::make_unique<krabs::kernel_trace>(m_sessionName);

  for (auto const &up : m_provs) {
    up->_attach(*m_trace, m_cb);
  }

  m_thread = std::thread([this] {
    try {
      m_trace->start();
    } catch (const std::exception &e) {
      std::string msg = std::string("KernelBlock: trace start failed: ") + e.what() + "\n";
      OutputDebugStringA(msg.c_str());
    } catch (...) {
      OutputDebugStringA("KernelBlock: trace start failed: unknown exception\n");
    }
  });
}

void KernelBlock::stop() {
  if (!m_trace) {
    return;
  }

  m_trace->stop();
  if (m_thread.joinable()) {
    m_thread.join();
  }

  m_provs.clear();
  m_trace.reset();
  m_cb = Callback{};
}

bool KernelBlock::stopWithDeadline(const Deadline &deadline) {
  if (!m_trace) {
    return true;
  }

  m_trace->stop();

  bool ok = true;
  if (m_thread.joinable()) {
    const auto rem = deadline.remaining_ms();
    const DWORD waitMs = static_cast<DWORD>(std::clamp<long long>(rem.count(), KernelBlockConstants::MIN_WAIT_MS, KernelBlockConstants::MAX_WAIT_MS));
    const HANDLE h = reinterpret_cast<HANDLE>(m_thread.native_handle());
    const DWORD res = WaitForSingleObject(h, waitMs);
    if (res == WAIT_OBJECT_0) {
      m_thread.join();
    } else {
      OutputDebugStringA(KernelBlockConstants::TIMEOUT_DETACH_MSG);
      m_thread.detach();
      ok = false;
    }
  }

  m_provs.clear();
  m_trace.reset();
  m_cb = Callback{};
  return ok;
}
