#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "pch.h"

#include <TlHelp32.h>
#include <evntcons.h>

#include <memory>
#include <set>
#include <string>
#include <optional>
#include <chrono>
#include <unordered_map>
#include <atomic>

#include <krabs.hpp>

#include <mutex>
#include "Caches.hpp"
#include "EventWriter.hpp"
#include "KernelBlock.hpp"
#include "ThreadAnalysisEngine.hpp"
#include "Threads.hpp"
#include "Deadline.hpp"
#include "UserBlock.hpp"

class ProcessMonitor {
public:
  struct GuidHash {
    size_t operator()(const GUID &g) const noexcept {
      const auto *p = reinterpret_cast<const uint64_t *>(&g);
      return std::hash<uint64_t>{}(p[0]) ^ (std::hash<uint64_t>{}(p[1]) << 1);
    }
  };
  struct GuidEq {
    bool operator()(const GUID &a, const GUID &b) const noexcept {
      return InlineIsEqualGUID(a, b);
    }
  };

  explicit ProcessMonitor(const std::wstring &exeName, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, const std::wstring &outPath) noexcept;
  explicit ProcessMonitor(const std::set<DWORD> &initialPids, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, std::wstring outPath) noexcept;

  std::set<DWORD> findPidsByName(const std::wstring &exeName) const;
  void logEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  bool waitForTarget(const Deadline &deadline, std::chrono::milliseconds pollInterval);
  bool stopWithDeadline(const Deadline &deadline);

  void start();
  void stop();

private:
  ThreadAnalysisEngine m_threadAnalysis;
  UserBlock m_user;
  KernelBlock m_kernel;
  Threads m_threads;
  Caches m_caches;
  std::mutex m_analysisMtx;
  mutable std::mutex m_targetPidsMtx;
  mutable std::mutex m_providerCountsMtx;
  std::unique_ptr<EventWriter> m_writer = nullptr;
  std::set<DWORD> m_targetPids;
  std::chrono::steady_clock::time_point m_lastTargetPidRefresh{};
  std::unordered_map<GUID, std::uint64_t, GuidHash, GuidEq> m_providerCounts;
  std::atomic<std::uint32_t> m_sysmonDebugLogged{0};
  std::optional<std::wstring> m_targetExeName;

private:
  void _refreshTargetPidsIfNeeded(bool forceRefresh, bool announceChanges);
  std::set<DWORD> _targetPidsSnapshot() const;
  void _recordProviderCount(const GUID &provider);
  void _emitProviderSummary() const;
  void _analyzeRecord(const EVENT_RECORD &record,
                      const krabs::trace_context &ctx);
  void _enableKernelProviders();
  void _enableUserProviders();
  void _enableSysmonChannel(std::stop_token stopToken);
  void _onKernelEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  void _onUserEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  bool _pidAllowed(const EVENT_RECORD &record, const krabs::trace_context &ctx);
};
