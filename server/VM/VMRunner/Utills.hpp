#pragma once
#include <chrono>
#include <functional>
#include <string>
#include <string_view>

namespace Utills {

using CommandExecutor = std::function<int(const std::string &cmd)>;

enum class VmPowerState {
  Running,
  Stopped,
  Unknown
};

void printBanner(bool isClosing = false);

int executeAndWaitRC(const std::string &cmd,
                     std::string *out = nullptr,
                     std::string *err = nullptr,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds::max(),
                     bool echoOutput = true);

bool waitForTools(const std::string &vmRunPath,
                  const std::string &sandboxPath,
                  int maxRetries = 60,
                  int sleepMs = 5000);

std::string ensureQuoted(const std::string &s);

std::string psQuote(const std::string &s);

std::string winQuote(std::string_view s);

int runPSInGuest(const std::string &vmRunPath,
                 const std::string &sandboxVmx,
                 std::string_view psCommand);
std::string dequote(std::string s);

bool guestPathExists(const std::string &vmRunPath,
                     const std::string &sandboxVmx,
                     std::string_view guestPath);

VmPowerState getVmPowerState(const std::string &vmRunPath,
                             const std::string &sandboxVmx);

bool closeVMWithExecutor(const std::string &vmRunPath,
                         const std::string &sandboxVmx,
                         const CommandExecutor &executor,
                         std::chrono::seconds fallbackDelay = std::chrono::seconds::zero());

bool closeVM(const std::string &vmRunPath, const std::string &sandboxVmx, const std::string &sandboxId);

constexpr int BUFFER_SIZE = 256;

} // namespace Utills
