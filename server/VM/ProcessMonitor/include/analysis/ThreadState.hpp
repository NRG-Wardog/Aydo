#pragma once
#include "pch.h"

struct ThreadState {
  DWORD ownerPid = 0;
  DWORD suspendActorPid = 0;
  DWORD contextActorPid = 0;
  DWORD resumeActorPid = 0;
  std::chrono::time_point<std::chrono::system_clock> lastSuspend{};
  std::chrono::time_point<std::chrono::system_clock> lastResume{};
  std::chrono::time_point<std::chrono::system_clock> lastContextChange{};
  std::chrono::time_point<std::chrono::system_clock> lastObserved{};
};
