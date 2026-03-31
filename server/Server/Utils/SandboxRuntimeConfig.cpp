#include "SandboxRuntimeConfig.hpp"

#include <algorithm>
#include <format>
#include <limits>
#include <string_view>

namespace Utils::SandboxRuntimeConfig {
namespace {

constexpr std::string_view SANDBOX_ROOT_KEY = "sandbox";

bool readRequiredString(const Json::Value &parent,
                        std::string_view key,
                        std::string &target,
                        std::string &error) {
  const std::string jsonPath =
      std::format("custom_config.{}.{}", SANDBOX_ROOT_KEY, key);
  if (!parent.isMember(key.data())) {
    error = std::format("Missing required sandbox config key '{}'", jsonPath);
    return false;
  }

  const Json::Value &value = parent[key.data()];
  if (!value.isString()) {
    error = std::format("Sandbox config key '{}' must be a string", jsonPath);
    return false;
  }

  target = value.asString();
  if (target.empty()) {
    error = std::format("Sandbox config key '{}' must not be empty", jsonPath);
    return false;
  }

  return true;
}

bool readRequiredPath(const Json::Value &parent,
                      std::string_view key,
                      std::filesystem::path &target,
                      std::string &error) {
  std::string value;
  if (!readRequiredString(parent, key, value, error)) {
    return false;
  }

  target = std::filesystem::path(value);
  return true;
}

bool readRequiredUInt(const Json::Value &parent,
                      std::string_view key,
                      unsigned int &target,
                      std::string &error) {
  const std::string jsonPath =
      std::format("custom_config.{}.{}", SANDBOX_ROOT_KEY, key);
  if (!parent.isMember(key.data())) {
    error = std::format("Missing required sandbox config key '{}'", jsonPath);
    return false;
  }

  const Json::Value &value = parent[key.data()];
  if (!value.isUInt() && !value.isUInt64() && !value.isInt() &&
      !value.isInt64()) {
    error = std::format("Sandbox config key '{}' must be an unsigned integer",
                        jsonPath);
    return false;
  }

  const Json::LargestInt parsed = value.asLargestInt();
  if (parsed <= 0) {
    error = std::format("Sandbox config key '{}' must be greater than zero",
                        jsonPath);
    return false;
  }
  if (parsed > std::numeric_limits<unsigned int>::max()) {
    error = std::format("Sandbox config key '{}' is out of range", jsonPath);
    return false;
  }

  target = static_cast<unsigned int>(parsed);

  return true;
}

bool containsEnvValue(const std::vector<std::pair<std::string, std::string>> &env,
                      std::string_view key,
                      std::string_view expectedValue) {
  return std::any_of(env.begin(), env.end(), [&](const auto &entry) {
    return entry.first == key && entry.second == expectedValue;
  });
}

bool reportSelfTest(bool condition,
                    std::string_view name,
                    std::string *failure) {
  if (condition) {
    return true;
  }

  if (failure != nullptr) {
    *failure = std::string(name);
  }
  return false;
}

Json::Value buildValidSandboxConfig() {
  Json::Value sandbox(Json::objectValue);
  sandbox["vmRunnerPath"] = R"(C:\Desktop\aydo\x64\Release\VMRunner.exe)";
  sandbox["vmRunPath"] =
      R"(C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe)";
  sandbox["analysisVmPath"] = R"(D:\veeeertoooaaalll\SANDBOX1\SANDBOX1.vmx)";
  sandbox["sandboxesDirectoryPath"] = R"(D:\veeeertoooaaalll)";
  sandbox["vmStartMode"] = "nogui";
  sandbox["guestUser"] = "Cyber_user";
  sandbox["guestPass"] = "1234";
  sandbox["guestSharedDir"] = R"(\\vmware-host\Shared Folders\Shared)";
  sandbox["shareFileName"] = "log.sqlite";
  sandbox["pmHostPath"] =
      R"(C:\Desktop\aydo\server\VM\ProcessMonitor\bin\x64\Release\ProcessMonitor.exe)";
  sandbox["pmGuestPath"] = R"(C:\Users\Cyber_user\Desktop\ProcessMonitor.exe)";
  sandbox["dllInjectorHostPath"] =
      R"(C:\Desktop\aydo\x64\Debug\ProcessRunnerDLL.dll)";
  sandbox["dllInjectorGuestPath"] =
      R"(C:\Users\Cyber_user\Desktop\InjectedDLL.dll)";
  sandbox["processRunnerHostPath"] =
      R"(C:\Desktop\aydo\x64\Debug\ProcessRunner.exe)";
  sandbox["processRunnerGuestPath"] =
      R"(C:\Users\Cyber_user\Desktop\ProcessRunner.exe)";
  sandbox["suspiciousWorkdirGuest"] =
      R"(C:\Users\Cyber_user\Desktop\checks)";
  sandbox["vmPowerOnMaxRetries"] = 60U;
  sandbox["vmPowerOnSleepMs"] = 2000U;
  sandbox["vmToolsMaxRetries"] = 60U;
  sandbox["vmToolsSleepMs"] = 5000U;
  sandbox["vmShutdownGraceMs"] = 5000U;

  Json::Value customConfig(Json::objectValue);
  customConfig[SANDBOX_ROOT_KEY.data()] = sandbox;
  return customConfig;
}

} // namespace

std::vector<std::pair<std::string, std::string>> Config::toEnvironment() const {
  return {
      {"VM_RUN_PATH", vmRunPath.string()},
      {"ANALYSIS_VM_PATH", analysisVmPath.string()},
      {"SANDBOXES_DIRECTORY_PATH", sandboxesDirectoryPath.string()},
      {"VM_START_MODE", vmStartMode},
      {"GUEST_USER", guestUser},
      {"GUEST_PASS", guestPass},
      {"GUEST_SHARED_DIR", guestSharedDir},
      {"SHARE_FILE_NAME", shareFileName},
      {"PM_FILE_PATH", pmHostPath.string()},
      {"PM_FILE_PATH_GUEST", pmGuestPath},
      {"DLL_INJECTOR_FILE_PATH", dllInjectorHostPath.string()},
      {"DLL_INJECTOR_FILE_PATH_GUEST", dllInjectorGuestPath},
      {"PROCCES_RUNNER_FILE_PATH", processRunnerHostPath.string()},
      {"PROCCES_RUNNER_FILE_PATH_GUEST", processRunnerGuestPath},
      {"SUSPICIOUS_WORKDIR_GUEST", suspiciousWorkdirGuest},
      {"VM_POWER_ON_MAX_RETRIES", std::to_string(vmPowerOnMaxRetries)},
      {"VM_POWER_ON_SLEEP_MS", std::to_string(vmPowerOnSleepMs)},
      {"VM_TOOLS_MAX_RETRIES", std::to_string(vmToolsMaxRetries)},
      {"VM_TOOLS_SLEEP_MS", std::to_string(vmToolsSleepMs)},
      {"VM_SHUTDOWN_GRACE_MS", std::to_string(vmShutdownGraceMs)},
  };
}

std::filesystem::path Config::sandboxDirectoryFor(std::string_view sandboxId) const {
  return sandboxesDirectoryPath / std::filesystem::path(std::string(sandboxId));
}

std::filesystem::path Config::sharedLogDbPath(std::string_view sandboxId) const {
  return sandboxDirectoryFor(sandboxId) / "shared" /
         std::filesystem::path(shareFileName);
}

LoadResult load(const Json::Value &customConfig) {
  if (!customConfig.isObject()) {
    return {std::nullopt,
            "Sandbox config is unavailable because custom_config is not an object"};
  }

  if (!customConfig.isMember(SANDBOX_ROOT_KEY.data())) {
    return {std::nullopt,
            std::format("Missing required sandbox config object 'custom_config.{}'",
                        SANDBOX_ROOT_KEY)};
  }

  const Json::Value &sandbox = customConfig[SANDBOX_ROOT_KEY.data()];
  if (!sandbox.isObject()) {
    return {std::nullopt,
            std::format("Sandbox config key 'custom_config.{}' must be an object",
                        SANDBOX_ROOT_KEY)};
  }

  Config config;
  std::string error;
  if (!readRequiredPath(sandbox, "vmRunnerPath", config.vmRunnerPath, error) ||
      !readRequiredPath(sandbox, "vmRunPath", config.vmRunPath, error) ||
      !readRequiredPath(sandbox, "analysisVmPath", config.analysisVmPath, error) ||
      !readRequiredPath(sandbox, "sandboxesDirectoryPath",
                        config.sandboxesDirectoryPath, error) ||
      !readRequiredString(sandbox, "vmStartMode", config.vmStartMode, error) ||
      !readRequiredString(sandbox, "guestUser", config.guestUser, error) ||
      !readRequiredString(sandbox, "guestPass", config.guestPass, error) ||
      !readRequiredString(sandbox, "guestSharedDir", config.guestSharedDir,
                          error) ||
      !readRequiredString(sandbox, "shareFileName", config.shareFileName, error) ||
      !readRequiredPath(sandbox, "pmHostPath", config.pmHostPath, error) ||
      !readRequiredString(sandbox, "pmGuestPath", config.pmGuestPath, error) ||
      !readRequiredPath(sandbox, "dllInjectorHostPath",
                        config.dllInjectorHostPath, error) ||
      !readRequiredString(sandbox, "dllInjectorGuestPath",
                          config.dllInjectorGuestPath, error) ||
      !readRequiredPath(sandbox, "processRunnerHostPath",
                        config.processRunnerHostPath, error) ||
      !readRequiredString(sandbox, "processRunnerGuestPath",
                          config.processRunnerGuestPath, error) ||
      !readRequiredString(sandbox, "suspiciousWorkdirGuest",
                          config.suspiciousWorkdirGuest, error) ||
      !readRequiredUInt(sandbox, "vmPowerOnMaxRetries",
                        config.vmPowerOnMaxRetries, error) ||
      !readRequiredUInt(sandbox, "vmPowerOnSleepMs",
                        config.vmPowerOnSleepMs, error) ||
      !readRequiredUInt(sandbox, "vmToolsMaxRetries",
                        config.vmToolsMaxRetries, error) ||
      !readRequiredUInt(sandbox, "vmToolsSleepMs", config.vmToolsSleepMs, error) ||
      !readRequiredUInt(sandbox, "vmShutdownGraceMs",
                        config.vmShutdownGraceMs, error)) {
    return {std::nullopt, std::move(error)};
  }

  return {std::move(config), {}};
}

bool runSelfTests(std::string *failure) {
  const Json::Value customConfig = buildValidSandboxConfig();
  const LoadResult loadResult = load(customConfig);
  if (!reportSelfTest(static_cast<bool>(loadResult),
                      "sandbox config resolves successfully", failure)) {
    return false;
  }

  const Config &config = *loadResult.config;
  if (!reportSelfTest(
          config.sharedLogDbPath("abc123") ==
              (std::filesystem::path(R"(D:\veeeertoooaaalll)") / "abc123" /
               "shared" / "log.sqlite"),
          "sandbox log path uses configured sandboxes directory", failure)) {
    return false;
  }

  const auto env = config.toEnvironment();
  if (!reportSelfTest(
          containsEnvValue(env, "SANDBOXES_DIRECTORY_PATH",
                           R"(D:\veeeertoooaaalll)"),
          "sandbox environment exports sandboxes directory", failure)) {
    return false;
  }

  Json::Value missingPathConfig = customConfig;
  missingPathConfig[SANDBOX_ROOT_KEY.data()].removeMember(
      "sandboxesDirectoryPath");
  const LoadResult missingPathResult = load(missingPathConfig);
  if (!reportSelfTest(
          !missingPathResult &&
              missingPathResult.error.find(
                  "custom_config.sandbox.sandboxesDirectoryPath") !=
                  std::string::npos,
          "missing sandboxesDirectoryPath returns deterministic error", failure)) {
    return false;
  }

  return true;
}

} // namespace Utils::SandboxRuntimeConfig
