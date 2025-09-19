#pragma once

#include <botan/hash.h>
#include <botan/hex.h>
#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include <Windows.h>
#include <tlhelp32.h>

struct RunningProcess {
  unsigned int pid;
  std::string path;
};

class Utils {
public:
  static std::string calculateHash(std::vector<uint8_t> data);
  static std::vector<RunningProcess> getRunningProcesses();
  static unsigned int getCurrentProcessID();
};
