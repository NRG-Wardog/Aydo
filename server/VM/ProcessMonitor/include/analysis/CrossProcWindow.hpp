#pragma once
#include "pch.h"

struct CrossProcWindow {
  std::chrono::time_point<std::chrono::system_clock> lastProcessAccess;
  std::chrono::time_point<std::chrono::system_clock> lastRemoteThread;
  std::chrono::time_point<std::chrono::system_clock> lastApcQueue;
};