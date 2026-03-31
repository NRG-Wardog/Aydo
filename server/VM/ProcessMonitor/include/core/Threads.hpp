#pragma once
#include <thread>

struct Threads {
  std::jthread kernel;
  std::jthread user;
  std::jthread sysmon;
};
