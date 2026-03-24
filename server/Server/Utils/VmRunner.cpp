#include "VmRunner.hpp"

#include <cstdlib>
#include <filesystem>
#include <format>
#include <mutex>
#include <thread>

#include <drogon/drogon.h>

#include "../Constants.hpp"
#include "Generic.hpp"

namespace Utils::VmRunner {

namespace {

std::string resolveVmRunnerPath() {
  const std::filesystem::path vmRunnerPathFs(Constants::VMRUNNER_PATH);
  const std::filesystem::path resolvedVmRunnerPath =
      vmRunnerPathFs.is_absolute() ? vmRunnerPathFs
                                   : std::filesystem::absolute(vmRunnerPathFs);
  return resolvedVmRunnerPath.string();
}

bool ensureVmRunnerExists(const std::string &vmRunnerPath) {
  if (const std::filesystem::path path(vmRunnerPath);
      !std::filesystem::exists(path)) {
    LOG_ERROR << "VMRunner path does not exist: " << vmRunnerPath;
    return false;
  }
  return true;
}

std::string wrapForCmd(const std::string &innerCmd) {
  return std::format(R"(cmd /c "{}")", innerCmd);
}

} // namespace

bool startVm(const std::string &sandboxId,
             const std::filesystem::path &payloadHostPath,
             int runtimeSeconds) {
  const std::string vmRunnerPath = resolveVmRunnerPath();
  if (!ensureVmRunnerExists(vmRunnerPath)) {
    return false;
  }

  const std::string payloadPath =
      std::filesystem::absolute(payloadHostPath).string();
  // On Windows, cmd.exe strips leading/trailing quotes when the first char is a quote.
  // Wrapping the entire command in quotes fixes this behavior.
  const std::string innerCmd = std::format(
      R"({} {} {} {})",
      Utils::Generic::quoteIfNeeded(vmRunnerPath),
      sandboxId,
      Utils::Generic::quoteIfNeeded(payloadPath),
      runtimeSeconds);
  const std::string cmd = wrapForCmd(innerCmd);

  LOG_INFO << "Launching VMRunner: " << cmd;
  const int rc = std::system(cmd.c_str());
  warmUpPoolAsync();
  if (rc != 0) {
    LOG_ERROR << "VMRunner failed with exit code " << rc
              << " (sandboxId=" << sandboxId << ")";
    return false;
  }

  LOG_INFO << "VMRunner completed successfully (sandboxId=" << sandboxId << ")";
  return true;
}

void warmUpPoolAsync() {
  static std::mutex warmupMutex;
  static bool warmupRunning = false;

  {
    const std::lock_guard<std::mutex> lock(warmupMutex);
    if (warmupRunning) {
      return;
    }
    warmupRunning = true;
  }

  std::thread([]() {
    const auto finish = []() {
      std::lock_guard<std::mutex> lock(warmupMutex);
      warmupRunning = false;
    };

    const std::string vmRunnerPath = resolveVmRunnerPath();
    if (!ensureVmRunnerExists(vmRunnerPath)) {
      finish();
      return;
    }

    const std::string innerCmd = std::format(
        R"({} --prepare-warm-pool)",
        Utils::Generic::quoteIfNeeded(vmRunnerPath));
    const std::string cmd = wrapForCmd(innerCmd);

    LOG_INFO << "Launching warm sandbox preloader: " << cmd;
    const int rc = std::system(cmd.c_str());
    if (rc != 0) {
      LOG_WARN << "Warm sandbox preloader exited with code " << rc;
    }

    finish();
  }).detach();
}

} // namespace Utils::VmRunner
