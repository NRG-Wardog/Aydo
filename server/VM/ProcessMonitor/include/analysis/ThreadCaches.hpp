#pragma once
#include "pch.h"
#include <chrono>
#include <optional>
#include <string>
#include "CrossProcWindow.hpp"
#include "NormalizedEvent.hpp"
#include "ThreadState.hpp"

class ThreadCaches {
  static constexpr auto TID_TTL = std::chrono::minutes(30);
  static constexpr auto XPROC_TTL = std::chrono::minutes(10);

public:
  void update(const NormalizedEvent &normEvent);
  void cleanup(std::chrono::time_point<std::chrono::system_clock> now);
  void rememberProcessImage(DWORD pid,
                            const std::string &image,
                            std::chrono::time_point<std::chrono::system_clock> now);
  [[nodiscard]] std::optional<std::string> findProcessImage(DWORD pid) const;

  bool hasRecentProcessAccess(DWORD sourcePid,
                              DWORD targetPid,
                              std::chrono::time_point<std::chrono::system_clock> now,
                              std::chrono::seconds window) const;

  std::optional<DWORD> findRecentSourceForTarget(
      DWORD targetPid,
      std::chrono::time_point<std::chrono::system_clock> now,
      std::chrono::seconds window) const;

  std::map<uint64_t, ThreadState> byTid;
  std::map<std::pair<DWORD, DWORD>, CrossProcWindow> crossProcWindows;

private:
  std::map<DWORD, std::pair<std::string, std::chrono::time_point<std::chrono::system_clock>>> m_processImageByPid;
};

