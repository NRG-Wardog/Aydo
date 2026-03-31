#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "Constants.hpp"
#include "LogName.hpp"
#include "Utills.hpp"

namespace {

struct CommandResult {
  int rc = -1;
  std::string out;
  std::string err;
};

using CommandRunner = std::function<CommandResult(const std::string &)>;

enum class StartupStageFailure {
  None,
  StartCommandFailed,
  VmPowerOnTimeout,
  MissingSharedFolderName,
  SharedFolderConfigFailed,
  VmPoweredOffDuringSharedFolderConfig,
};

struct StartupStageResult {
  StartupStageFailure failure = StartupStageFailure::None;
  std::string message;

  [[nodiscard]] bool succeeded() const {
    return failure == StartupStageFailure::None;
  }
};

bool reportSelfTest(bool condition, std::string_view name) {
  if (condition) {
    std::cout << "[PASS] " << name << std::endl;
    return true;
  }

  std::cerr << "[FAIL] " << name << std::endl;
  return false;
}

class ScopedStepTimer {
 public:
  explicit ScopedStepTimer(std::string label)
      : label_(std::move(label)),
        start_(std::chrono::steady_clock::now()) {}

  ~ScopedStepTimer() {
    const auto elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_);
    std::cout << "    [timing] " << label_ << ": " << elapsedMs.count()
              << "ms" << std::endl;
  }

 private:
  std::string label_;
  std::chrono::steady_clock::time_point start_;
};

std::string toLowerCopy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return value;
}

std::string combinedOutput(const CommandResult &result) {
  if (result.out.empty()) {
    return result.err;
  }
  if (result.err.empty()) {
    return result.out;
  }
  return result.out + "\n" + result.err;
}

std::string describeCommandResult(const CommandResult &result) {
  const std::string output = combinedOutput(result);
  if (output.empty()) {
    return std::format("rc={}", result.rc);
  }
  return std::format("rc={} output={}", result.rc, output);
}

std::string trimCopy(std::string value) {
  const auto isNotSpace = [](unsigned char ch) {
    return !std::isspace(ch);
  };

  const auto first = std::find_if(value.begin(), value.end(), isNotSpace);
  if (first == value.end()) {
    return {};
  }

  const auto last = std::find_if(value.rbegin(), value.rend(), isNotSpace).base();
  return std::string(first, last);
}

std::string singleLineForLog(std::string value, size_t maxLen = 320) {
  std::replace(value.begin(), value.end(), '\r', ' ');
  std::replace(value.begin(), value.end(), '\n', ' ');
  value = trimCopy(std::move(value));
  if (value.size() <= maxLen) {
    return value;
  }
  return value.substr(0, maxLen) + "...";
}

std::string describePowerStateProbe(const Utills::VmPowerStateDetails &details) {
  std::string description = std::format(
      "state={} vmrunListRc={}",
      Utills::vmPowerStateToString(details.state),
      details.rc);

  const std::string output = singleLineForLog(
      details.out.empty() ? details.err : combinedOutput({details.rc, details.out, details.err}));
  if (!output.empty()) {
    description += std::format(" vmrunListOutput={}", output);
  }

  return description;
}

std::string buildPowerOnTimeoutHint(const Utills::VmPowerStateDetails &details) {
  if (details.rc != 0) {
    return "vmrun list failed while polling power state; verify VM_RUN_PATH, VMware installation, and permissions on this machine";
  }
  if (details.state == Utills::VmPowerState::Stopped) {
    return "vmrun start returned without error, but the sandbox VM never appeared in 'vmrun list'; check VMware UI for pending prompts, locked VM files, or increase vmPowerOnMaxRetries on slower machines";
  }
  return "VM power state stayed unknown; inspect vmrun output above and the VMware logs for this sandbox clone";
}

bool isVmNotPoweredOnError(const CommandResult &result) {
  const std::string output = toLowerCopy(combinedOutput(result));
  return output.find("not powered on") != std::string::npos ||
         output.find("not running") != std::string::npos;
}

bool isMissingSharedFolderError(const CommandResult &result) {
  const std::string output = toLowerCopy(combinedOutput(result));
  return output.find("shared folder") != std::string::npos &&
         (output.find("not found") != std::string::npos ||
          output.find("does not exist") != std::string::npos ||
          output.find("no such") != std::string::npos);
}

bool validateExistingFile(const std::filesystem::path &path,
                          std::string_view label) {
  if (!std::filesystem::exists(path)) {
    std::cerr << "\tFAIL missing " << label << ": " << path.string()
              << std::endl;
    return false;
  }
  if (!std::filesystem::is_regular_file(path)) {
    std::cerr << "\tFAIL " << label << " is not a file: " << path.string()
              << std::endl;
    return false;
  }
  return true;
}

bool ensureDirectoryExists(const std::filesystem::path &path,
                           std::string_view label) {
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  if (ec) {
    std::cerr << "\tFAIL create " << label << " '" << path.string()
              << "': " << ec.message() << std::endl;
    return false;
  }
  return true;
}

unsigned int getEnvUIntOrDefaultLocal(const char *name, unsigned int fallback) {
  if (const char *value = std::getenv(name)) {
    char *end = nullptr;
    const unsigned long parsed = std::strtoul(value, &end, 10);
    if (end != value && *end == '\0' &&
        parsed <= std::numeric_limits<unsigned int>::max()) {
      return static_cast<unsigned int>(parsed);
    }
  }
  return fallback;
}

StartupStageResult startVmAndConfigureSharedFolder(
    const std::string &vmRunPath,
    const std::string &sandboxVmx,
    std::string_view vmStartMode,
    std::string_view sharedFolderName,
    const std::filesystem::path &hostShared,
    int powerOnMaxRetries,
    int powerOnSleepMs,
    const std::function<Utills::VmPowerStateDetails()> &powerStateProbe,
    const CommandRunner &commandRunner) {
  const std::string quotedVmRunPath = Utills::winQuote(Utills::dequote(vmRunPath));
  const std::string startCmd = std::format(
      R"({} -T ws start {} {})",
      quotedVmRunPath,
      sandboxVmx,
      Utills::winQuote(vmStartMode));
  const CommandResult startResult = commandRunner(startCmd);
  if (startResult.rc != 0) {
    return {StartupStageFailure::StartCommandFailed,
            std::format("start failed: {}", describeCommandResult(startResult))};
  }

  const std::string startOutput = singleLineForLog(combinedOutput(startResult));
  if (!startOutput.empty()) {
    std::cout << "    [startup] vmrun start output: " << startOutput
              << std::endl;
  }

  Utills::VmPowerStateDetails lastProbe;
  bool reachedRunning = false;
  for (int attempt = 0; attempt < powerOnMaxRetries; ++attempt) {
    lastProbe = powerStateProbe();
    std::cout << "    [startup] power-state probe " << (attempt + 1) << '/'
              << powerOnMaxRetries << ": "
              << describePowerStateProbe(lastProbe) << std::endl;
    if (lastProbe.state == Utills::VmPowerState::Running) {
      reachedRunning = true;
      break;
    }

    if (attempt + 1 < powerOnMaxRetries) {
      std::this_thread::sleep_for(std::chrono::milliseconds(powerOnSleepMs));
    }
  }

  if (!reachedRunning) {
    const long long totalWaitMs =
        static_cast<long long>(powerOnMaxRetries) * powerOnSleepMs;
    return {StartupStageFailure::VmPowerOnTimeout,
            std::format(
                "VM did not reach the running state after {} retries x {}ms ({}ms total). startResult={} lastProbe={} hint={}",
                powerOnMaxRetries,
                powerOnSleepMs,
                totalWaitMs,
                describeCommandResult(startResult),
                describePowerStateProbe(lastProbe),
                buildPowerOnTimeoutHint(lastProbe))};
  }

  if (sharedFolderName.empty()) {
    return {StartupStageFailure::MissingSharedFolderName,
            std::format(
                "could not derive shared folder name from GUEST_SHARED_DIR='{}'",
                std::string(GUEST_SHARED_DIR))};
  }

  const std::string removeCmd = std::format(
      R"({} -T ws removeSharedFolder {} {})",
      quotedVmRunPath,
      sandboxVmx,
      Utills::winQuote(sharedFolderName));
  const CommandResult removeResult = commandRunner(removeCmd);
  if (removeResult.rc != 0) {
    if (isVmNotPoweredOnError(removeResult)) {
      return {StartupStageFailure::VmPoweredOffDuringSharedFolderConfig,
              std::format("VM powered off before shared-folder removal: {}",
                          describeCommandResult(removeResult))};
    }
    if (!isMissingSharedFolderError(removeResult)) {
      return {StartupStageFailure::SharedFolderConfigFailed,
              std::format("removeSharedFolder failed: {}",
                          describeCommandResult(removeResult))};
    }
  }

  const std::string addCmd = std::format(
      R"({} -T ws addSharedFolder {} {} {})",
      quotedVmRunPath,
      sandboxVmx,
      Utills::winQuote(sharedFolderName),
      Utills::winQuote(hostShared.string()));
  const CommandResult addResult = commandRunner(addCmd);
  if (addResult.rc != 0) {
    if (isVmNotPoweredOnError(addResult)) {
      return {StartupStageFailure::VmPoweredOffDuringSharedFolderConfig,
              std::format("VM powered off before shared-folder add: {}",
                          describeCommandResult(addResult))};
    }
    return {StartupStageFailure::SharedFolderConfigFailed,
            std::format("addSharedFolder failed: {}",
                        describeCommandResult(addResult))};
  }

  return {};
}

int runSelfTests() {
  auto runCloseVMCase =
      [](std::string_view name,
         const std::vector<int> &returnCodes,
         bool expectedSuccess,
         size_t expectedCommandCount) {
        std::vector<std::string> commands;
        size_t nextReturnCode = 0;
        const bool success = Utills::closeVMWithExecutor(
            "vmrun",
            "\"sandbox.vmx\"",
            [&](const std::string &cmd) -> int {
              commands.push_back(cmd);
              if (nextReturnCode < returnCodes.size()) {
                return returnCodes[nextReturnCode++];
              }
              return 1;
            });

        const bool hasSoftStop =
            !commands.empty() &&
            commands[0].find(" soft") != std::string::npos;
        const bool hasHardStop =
            expectedCommandCount < 2 ||
            (commands.size() >= 2 &&
             commands[1].find(" hard") != std::string::npos);

        return reportSelfTest(
            success == expectedSuccess &&
                commands.size() == expectedCommandCount &&
                hasSoftStop && hasHardStop,
            name);
      };

  auto makeCommandRunner = [](const std::vector<CommandResult> &results,
                              std::vector<std::string> &commands) {
    return [&](const std::string &cmd) -> CommandResult {
      commands.push_back(cmd);
      const size_t index = commands.size() - 1;
      if (index < results.size()) {
        return results[index];
      }
      return {1, {}, "unexpected command"};
    };
  };

  auto makePowerStateProbeSequence = [](const std::vector<Utills::VmPowerState> &states) {
    size_t nextState = 0;
    return [states, nextState]() mutable {
      const size_t index = std::min(nextState, states.size() - 1);
      if (nextState + 1 < states.size()) {
        ++nextState;
      }
      Utills::VmPowerStateDetails details;
      details.state = states[index];
      details.rc = 0;
      details.command = "vmrun -T ws list";
      return details;
    };
  };

  bool allPassed = true;
  allPassed &= runCloseVMCase("closeVM succeeds after a soft stop", {0}, true, 1);
  allPassed &= runCloseVMCase("closeVM falls back to a hard stop", {1, 0}, true, 2);
  allPassed &= runCloseVMCase("closeVM reports failure when both stop commands fail",
                              {1, 1}, false, 2);

  {
    std::vector<Utills::VmPowerState> states = {
        Utills::VmPowerState::Stopped,
        Utills::VmPowerState::Unknown,
        Utills::VmPowerState::Running,
    };
    size_t nextState = 0;
    int calls = 0;
    const bool success = Utills::waitForVmPowerState(
        [&]() {
          ++calls;
          const size_t index = std::min(nextState, states.size() - 1);
          if (nextState + 1 < states.size()) {
            ++nextState;
          }
          return states[index];
        },
        Utills::VmPowerState::Running,
        4,
        0);
    allPassed &= reportSelfTest(
        success && calls == 3,
        "waitForVmPowerState succeeds after transition to Running");
  }

  {
    std::vector<std::string> commands;
    const auto result = startVmAndConfigureSharedFolder(
        "vmrun",
        "\"sandbox.vmx\"",
        "nogui",
        "Shared",
        R"(D:\host shared)",
        3,
        0,
        makePowerStateProbeSequence(
            {Utills::VmPowerState::Stopped, Utills::VmPowerState::Running}),
        makeCommandRunner({{0, {}, {}}, {0, {}, {}}, {0, {}, {}}}, commands));
    allPassed &= reportSelfTest(
        result.succeeded() && commands.size() == 3 &&
            commands[2].find("addSharedFolder") != std::string::npos,
        "startup stage succeeds once VM reaches Running");
  }

  {
    std::vector<std::string> commands;
    const auto result = startVmAndConfigureSharedFolder(
        "vmrun",
        "\"sandbox.vmx\"",
        "nogui",
        "Shared",
        R"(D:\host shared)",
        2,
        0,
        makePowerStateProbeSequence(
            {Utills::VmPowerState::Stopped, Utills::VmPowerState::Stopped}),
        makeCommandRunner({{0, {}, {}}}, commands));
    allPassed &= reportSelfTest(
        result.failure == StartupStageFailure::VmPowerOnTimeout &&
            commands.size() == 1 &&
            commands[0].find(" start ") != std::string::npos,
        "startup stage fails before shared-folder commands if VM never powers on");
  }

  {
    std::vector<std::string> commands;
    const auto result = startVmAndConfigureSharedFolder(
        "vmrun",
        "\"sandbox.vmx\"",
        "nogui",
        "Shared",
        R"(D:\host shared)",
        1,
        0,
        makePowerStateProbeSequence({Utills::VmPowerState::Running}),
        makeCommandRunner({{0, {}, {}},
                           {1, {}, "The shared folder was not found"},
                           {0, {}, {}}},
                          commands));
    allPassed &= reportSelfTest(
        result.succeeded() && commands.size() == 3,
        "removeSharedFolder missing-folder error is ignored");
  }

  {
    std::vector<std::string> commands;
    const auto result = startVmAndConfigureSharedFolder(
        "vmrun",
        "\"sandbox.vmx\"",
        "nogui",
        "Shared",
        R"(D:\host shared)",
        1,
        0,
        makePowerStateProbeSequence({Utills::VmPowerState::Running}),
        makeCommandRunner({{0, {}, {}},
                           {0, {}, {}},
                           {1, {}, "The virtual machine is not powered on"}},
                          commands));
    allPassed &= reportSelfTest(
        result.failure ==
            StartupStageFailure::VmPoweredOffDuringSharedFolderConfig &&
            commands.size() == 3,
        "addSharedFolder powered-off error is surfaced as a startup-state failure");
  }

  return allPassed ? EXIT_SUCCESS : EXIT_FAILURE;
}

} // namespace

int main(int argc, char *argv[]) {
  if (argc == 2 && std::string_view(argv[1]) == "--self-test") {
    return runSelfTests();
  }

  if (argc < 3 || argc > 4) {
    std::cerr << "Usage: " << argv[0] << " <sandbox_id> <virus_path> [runTime]"
              << std::endl;
    return EXIT_FAILURE;
  }

  const std::string sandboxId(argv[1]);
  const std::filesystem::path suspiciousHostPath(argv[2]);
  const int runTimeSec = (argc == 4) ? std::atoi(argv[3]) : DEFUALT_TIME_CHECK;

  const std::string vmRunPath = std::string(VM_RUN_PATH);
  const std::filesystem::path vmRunExecutable(Utills::dequote(vmRunPath));
  const std::filesystem::path baseVmxPath(
      Utills::dequote(std::string(ANALYSIS_VM_PATH)));
  const std::filesystem::path sandboxesDirectory(
      Utills::dequote(std::string(SANDBOXES_DIRECTORY_PATH)));
  const std::filesystem::path vmDir = sandboxesDirectory / sandboxId;
  const std::filesystem::path sandboxVmxPath = vmDir / (sandboxId + ".vmx");
  const std::filesystem::path hostShared = vmDir / "shared";
  const std::string sandboxVmx = Utills::winQuote(sandboxVmxPath.string());

  std::filesystem::path guestSharedPath(GUEST_SHARED_DIR);
  guestSharedPath = guestSharedPath.lexically_normal();
  const std::string sharedFolderName = guestSharedPath.filename().string();

  const std::string pmHostAbs =
      std::filesystem::absolute(std::filesystem::path(std::string(PM_FILE_PATH)))
          .string();
  const std::string dllInjectorHostAbs =
      std::filesystem::absolute(
          std::filesystem::path(std::string(DLL_INJECTOR_FILE_PATH)))
          .string();
  const std::string processRunnerHostAbs =
      std::filesystem::absolute(
          std::filesystem::path(std::string(PROCCES_RUNNER_FILE_PATH)))
          .string();
  const std::string suspiciousHostAbs =
      std::filesystem::absolute(suspiciousHostPath).string();

  if (!validateExistingFile(vmRunExecutable, "vmrun executable") ||
      !validateExistingFile(baseVmxPath, "analysis VMX") ||
      !validateExistingFile(std::filesystem::path(pmHostAbs),
                            "ProcessMonitor host binary") ||
      !validateExistingFile(std::filesystem::path(dllInjectorHostAbs),
                            "DLL injector host binary") ||
      !validateExistingFile(std::filesystem::path(processRunnerHostAbs),
                            "ProcessRunner host binary") ||
      !validateExistingFile(std::filesystem::path(suspiciousHostAbs),
                            "suspicious payload") ||
      !ensureDirectoryExists(sandboxesDirectory, "sandboxes directory") ||
      !ensureDirectoryExists(vmDir, "sandbox directory") ||
      !ensureDirectoryExists(hostShared, "host shared directory")) {
    return EXIT_FAILURE;
  }

  const std::string guestWorkDir = std::string(SUSPICIOUS_WORKDIR_GUEST);
  const std::string guestPmPath = std::string(PM_FILE_PATH_GUEST);
  const std::string guestDllInjectorPath =
      std::string(DLL_INJECTOR_FILE_PATH_GUEST);
  const std::string guestProcessRunnerPath =
      std::string(PROCCES_RUNNER_FILE_PATH_GUEST);
  const std::string guestSuspiciousFilePath =
      (std::filesystem::path(guestWorkDir) /
       std::filesystem::path(suspiciousHostPath).filename())
          .string();
  const std::string guestLogPath =
      (std::filesystem::path(GUEST_SHARED_DIR) /
       std::filesystem::path(SHARE_FILE_NAME))
          .string();
  const std::string hostLogPath =
      (hostShared / std::filesystem::path(SHARE_FILE_NAME)).string();
  const unsigned int vmPowerOnMaxRetries =
      getEnvUIntOrDefaultLocal("VM_POWER_ON_MAX_RETRIES", 60);
  const unsigned int vmPowerOnSleepMs =
      getEnvUIntOrDefaultLocal("VM_POWER_ON_SLEEP_MS", 2000);
  const std::string quotedVmRunPath = Utills::winQuote(Utills::dequote(vmRunPath));
  const auto totalStart = std::chrono::steady_clock::now();
  const unsigned long long powerOnBudgetMs =
      static_cast<unsigned long long>(vmPowerOnMaxRetries) * vmPowerOnSleepMs;

  std::cout << "[config] Sandbox launch summary" << std::endl;
  std::cout << "\tsandboxId: " << sandboxId << std::endl;
  std::cout << "\tvmrun: " << vmRunExecutable.string() << std::endl;
  std::cout << "\tbase VMX: " << baseVmxPath.string() << std::endl;
  std::cout << "\tsandbox VMX: " << sandboxVmxPath.string() << std::endl;
  std::cout << "\thost shared dir: " << hostShared.string() << std::endl;
  std::cout << "\tguest shared dir: " << GUEST_SHARED_DIR << std::endl;
  std::cout << "\tshared folder name: " << sharedFolderName << std::endl;
  std::cout << "\tpayload host path: " << suspiciousHostAbs << std::endl;
  std::cout << "\tpower-on timeout budget: " << powerOnBudgetMs << "ms ("
            << vmPowerOnMaxRetries << " x " << vmPowerOnSleepMs << "ms)"
            << std::endl;

  auto runCommand = [](const std::string &cmd) -> CommandResult {
    CommandResult result;
    result.rc = Utills::executeAndWaitRC(cmd, &result.out, &result.err);
    return result;
  };

  auto failWithOptionalShutdown =
      [&](std::string_view message, bool shouldCloseVm) {
        std::cerr << "\tFAIL " << message << std::endl;
        if (shouldCloseVm) {
          Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
        }
        return EXIT_FAILURE;
      };

  auto requireCommand = [&](std::string_view label,
                            const std::string &cmd) -> bool {
    const CommandResult result = runCommand(cmd);
    if (result.rc == 0) {
      return true;
    }
    std::cerr << "\tFAIL " << label << ' ' << describeCommandResult(result)
              << std::endl;
    Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
    return false;
  };

  std::cout << "[1.0/7] Clone linked VM if needed" << std::endl;
  {
    ScopedStepTimer timer("clone linked VM");
    if (!std::filesystem::exists(sandboxVmxPath)) {
      const std::string cmd = std::format(
          R"({} -T ws clone {} {} linked -cloneName={})",
          quotedVmRunPath,
          Utills::winQuote(baseVmxPath.string()),
          sandboxVmx,
          Utills::winQuote(sandboxId));
      const CommandResult result = runCommand(cmd);
      if (result.rc != 0) {
        return failWithOptionalShutdown(
            std::format("clone {}", describeCommandResult(result)), false);
      }
    }
  }

  std::cout << "[1.1/7] Start VM and configure shared folder" << std::endl;
  {
    ScopedStepTimer timer("start VM and configure shared folder");
    const StartupStageResult result = startVmAndConfigureSharedFolder(
        vmRunPath,
        sandboxVmx,
        VM_START_MODE,
        sharedFolderName,
        hostShared,
        static_cast<int>(vmPowerOnMaxRetries),
        static_cast<int>(vmPowerOnSleepMs),
        [&]() { return Utills::probeVmPowerState(vmRunPath, sandboxVmx); },
        runCommand);
    if (!result.succeeded()) {
      return failWithOptionalShutdown(result.message, true);
    }
  }

  std::cout << "[1.2/7] Wait for VMware Tools (" << VM_TOOLS_MAX_RETRIES
            << " retries x " << VM_TOOLS_SLEEP_MS << "ms)" << std::endl;
  {
    ScopedStepTimer timer("wait for VMware Tools");
    if (!Utills::waitForTools(vmRunPath, sandboxVmx,
                              static_cast<int>(VM_TOOLS_MAX_RETRIES),
                              static_cast<int>(VM_TOOLS_SLEEP_MS))) {
      return failWithOptionalShutdown("VMware Tools not ready", true);
    }
  }

  std::cout << "[1.3/7] Enable shared folders in guest" << std::endl;
  {
    ScopedStepTimer timer("enable shared folders");
    const CommandResult enableResult = runCommand(std::format(
        R"({} -T ws enableSharedFolders {})", quotedVmRunPath, sandboxVmx));
    if (enableResult.rc != 0) {
      std::cerr << "\tWARN enableSharedFolders "
                << describeCommandResult(enableResult)
                << " (shared folders may already be enabled)" << std::endl;
    }

    if (!requireCommand(
            "shared folder not visible in guest:",
            std::format(
                R"({} -T ws -gu {} -gp {} directoryExistsInGuest {} {})",
                quotedVmRunPath,
                std::string(GUEST_USER),
                std::string(GUEST_PASS),
                sandboxVmx,
                Utills::ensureQuoted(std::string(GUEST_SHARED_DIR))))) {
      return EXIT_FAILURE;
    }
  }

  std::cout << "[2.0/7] Create guest work dir: " << guestWorkDir << std::endl;
  {
    ScopedStepTimer timer("create guest work dir");
    const CommandResult existsResult = runCommand(std::format(
        R"({} -T ws -gu {} -gp {} directoryExistsInGuest {} {})",
        quotedVmRunPath,
        std::string(GUEST_USER),
        std::string(GUEST_PASS),
        sandboxVmx,
        Utills::ensureQuoted(guestWorkDir)));
    if (existsResult.rc != 0 &&
        !requireCommand(
            "createDirectory",
            std::format(
                R"({} -T ws -gu {} -gp {} createDirectoryInGuest {} {})",
                quotedVmRunPath,
                std::string(GUEST_USER),
                std::string(GUEST_PASS),
                sandboxVmx,
                Utills::ensureQuoted(guestWorkDir)))) {
      return EXIT_FAILURE;
    }
  }

  auto copyToGuest = [&](std::string_view label,
                         const std::string &hostPath,
                         const std::string &guestPath) -> bool {
    std::cout << label << std::endl;
    ScopedStepTimer timer{std::string(label)};
    return requireCommand(
        "copy",
        std::format(
            R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
            quotedVmRunPath,
            std::string(GUEST_USER),
            std::string(GUEST_PASS),
            sandboxVmx,
            Utills::ensureQuoted(hostPath),
            Utills::ensureQuoted(guestPath)));
  };

  if (!copyToGuest("[2.1/7] Copy monitor -> guest", pmHostAbs, guestPmPath) ||
      !copyToGuest("[2.2/7] Copy suspicious -> guest", suspiciousHostAbs,
                   guestSuspiciousFilePath) ||
      !copyToGuest("[2.3/7] Copy dllinjector -> guest", dllInjectorHostAbs,
                   guestDllInjectorPath) ||
      !copyToGuest("[2.4/7] Copy processRunner -> guest", processRunnerHostAbs,
                   guestProcessRunnerPath)) {
    return EXIT_FAILURE;
  }

  std::cout << "[3.0/7] Start monitor in guest" << std::endl;
  {
    ScopedStepTimer timer("start monitor");
    if (!requireCommand(
            "run monitor",
            std::format(
                R"({} -T ws -gu {} -gp {} runProgramInGuest {} -noWait {} {} {}{})",
                quotedVmRunPath,
                std::string(GUEST_USER),
                std::string(GUEST_PASS),
                sandboxVmx,
                Utills::ensureQuoted(guestPmPath),
                Utills::ensureQuoted(guestSuspiciousFilePath),
                Utills::ensureQuoted(guestLogPath),
                (runTimeSec > 0 ? std::format(" {}", runTimeSec)
                                : std::string{})))) {
      return EXIT_FAILURE;
    }
  }

  std::cout << "[3.1/7] Start Process Runner in guest" << std::endl;
  {
    ScopedStepTimer timer("start process runner");
    if (!requireCommand(
            "run payload",
            std::format(
                R"({} -T ws -gu {} -gp {} runProgramInGuest {} -noWait {} {} {} {})",
                quotedVmRunPath,
                std::string(GUEST_USER),
                std::string(GUEST_PASS),
                sandboxVmx,
                Utills::ensureQuoted(guestProcessRunnerPath),
                Utills::ensureQuoted(guestSuspiciousFilePath),
                Utills::ensureQuoted(guestDllInjectorPath),
                Utills::ensureQuoted(guestWorkDir)))) {
      return EXIT_FAILURE;
    }
  }

  std::cout << "[4/7] Let payload run for " << runTimeSec << "s" << std::endl;
  {
    ScopedStepTimer timer("payload runtime window");
    int remainingSeconds = runTimeSec;
    while (remainingSeconds > 0) {
      const int sleepChunk = std::min(remainingSeconds, 5);
      std::this_thread::sleep_for(std::chrono::seconds(sleepChunk));
      remainingSeconds -= sleepChunk;
      std::cout << "    [runtime] remaining " << remainingSeconds << "s"
                << std::endl;
    }
  }

  std::cout << "[5/7] Copy log guest->host" << std::endl;
  {
    ScopedStepTimer timer("verify shared log availability");
    std::cout << "\tExpected guest DB path: " << guestLogPath << std::endl;
    std::cout << "\tExpected host  DB path: " << hostLogPath << std::endl;
    if (!std::filesystem::exists(hostLogPath)) {
      return failWithOptionalShutdown(
          std::format("DB file NOT found on host path: {}", hostLogPath), true);
    }
    std::cout << "\tDB file exists on host." << std::endl;
  }

  std::cout << "[6/7] Shutdown VM" << std::endl;
  {
    ScopedStepTimer timer("shutdown VM");
    if (!Utills::closeVM(vmRunPath, sandboxVmx, sandboxId)) {
      std::wcerr << "Something went wrong with stop." << std::endl;
      Utills::printBanner(true);
      return EXIT_FAILURE;
    }
  }

  const auto totalElapsedMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - totalStart);
  std::cout << "[7/7] Total VM workflow time: " << totalElapsedMs.count()
            << "ms" << std::endl;
  std::cout << "Done." << std::endl;
  Utills::printBanner(true);
  return EXIT_SUCCESS;
}
