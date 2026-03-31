#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <json/json.h>

namespace Utils::SandboxRuntimeConfig {

struct Config {
  std::filesystem::path vmRunnerPath;
  std::filesystem::path vmRunPath;
  std::filesystem::path analysisVmPath;
  std::filesystem::path sandboxesDirectoryPath;
  std::string vmStartMode;
  std::string guestUser;
  std::string guestPass;
  std::string guestSharedDir;
  std::string shareFileName;
  std::filesystem::path pmHostPath;
  std::string pmGuestPath;
  std::filesystem::path dllInjectorHostPath;
  std::string dllInjectorGuestPath;
  std::filesystem::path processRunnerHostPath;
  std::string processRunnerGuestPath;
  std::string suspiciousWorkdirGuest;
  unsigned int vmPowerOnMaxRetries = 0;
  unsigned int vmPowerOnSleepMs = 0;
  unsigned int vmToolsMaxRetries = 0;
  unsigned int vmToolsSleepMs = 0;
  unsigned int vmShutdownGraceMs = 0;

  [[nodiscard]] std::vector<std::pair<std::string, std::string>> toEnvironment() const;
  [[nodiscard]] std::filesystem::path sandboxDirectoryFor(std::string_view sandboxId) const;
  [[nodiscard]] std::filesystem::path sharedLogDbPath(std::string_view sandboxId) const;
};

struct LoadResult {
  std::optional<Config> config;
  std::string error;

  [[nodiscard]] explicit operator bool() const {
    return config.has_value();
  }
};

[[nodiscard]] LoadResult load(const Json::Value &customConfig);
[[nodiscard]] bool runSelfTests(std::string *failure = nullptr);

} // namespace Utils::SandboxRuntimeConfig
