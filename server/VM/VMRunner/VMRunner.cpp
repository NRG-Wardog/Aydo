#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "Constants.hpp"
#include "LogName.hpp"
#include "Utills.hpp"

namespace fs = std::filesystem;

namespace {

constexpr std::string_view WARM_LOCKS_DIR_NAME = ".warm-locks";
constexpr std::string_view WARM_STATE_FILE_NAME = ".warm-state";

enum class WarmSandboxState {
  Cold,
  Preparing,
  Ready,
  Busy,
  Failed
};

struct SandboxPaths {
  std::string sandboxId;
  fs::path sandboxDir;
  std::string sandboxVmxRaw;
  std::string sandboxVmx;
  fs::path hostShared;
};

class ScopedStepTimer {
 public:
  explicit ScopedStepTimer(std::string label)
      : label_(std::move(label)),
        start_(std::chrono::steady_clock::now()) {}

  ~ScopedStepTimer() {
    const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_);
    std::cout << "    [timing] " << label_ << ": "
              << elapsedMs.count() << "ms" << std::endl;
  }

 private:
  std::string label_;
  std::chrono::steady_clock::time_point start_;
};

class SandboxLock {
 public:
  SandboxLock() = default;

  SandboxLock(const SandboxLock &) = delete;
  SandboxLock &operator=(const SandboxLock &) = delete;

  SandboxLock(SandboxLock &&other) noexcept
      : lockPath_(std::move(other.lockPath_)),
        locked_(std::exchange(other.locked_, false)) {}

  SandboxLock &operator=(SandboxLock &&other) noexcept {
    if (this != &other) {
      release();
      lockPath_ = std::move(other.lockPath_);
      locked_ = std::exchange(other.locked_, false);
    }
    return *this;
  }

  ~SandboxLock() {
    release();
  }

  [[nodiscard]] static std::optional<SandboxLock> tryAcquire(
      const fs::path &poolRoot,
      const std::string &sandboxId) {
    std::error_code ec;
    const fs::path locksDir = poolRoot / std::string(WARM_LOCKS_DIR_NAME);
    fs::create_directories(locksDir, ec);
    if (ec) {
      return std::nullopt;
    }

    const fs::path lockPath = locksDir / sandboxId;
    ec.clear();
    if (!fs::create_directory(lockPath, ec)) {
      return std::nullopt;
    }

    SandboxLock lock;
    lock.lockPath_ = lockPath;
    lock.locked_ = true;
    return lock;
  }

 private:
  void release() {
    if (!locked_) {
      return;
    }

    std::error_code ec;
    fs::remove(lockPath_, ec);
    locked_ = false;
  }

  fs::path lockPath_;
  bool locked_ = false;
};

static bool reportSelfTest(bool condition, std::string_view name) {
  if (condition) {
    std::cout << "[PASS] " << name << std::endl;
    return true;
  }

  std::cerr << "[FAIL] " << name << std::endl;
  return false;
}

static int runSelfTests() {
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

  bool allPassed = true;
  allPassed &= runCloseVMCase(
      "closeVM succeeds after a soft stop",
      {0},
      true,
      1);
  allPassed &= runCloseVMCase(
      "closeVM falls back to a hard stop",
      {1, 0},
      true,
      2);
  allPassed &= runCloseVMCase(
      "closeVM reports failure when both stop commands fail",
      {1, 1},
      false,
      2);

  return allPassed ? EXIT_SUCCESS : EXIT_FAILURE;
}

SandboxPaths buildSandboxPaths(const std::string &sandboxId) {
  SandboxPaths paths;
  paths.sandboxId = sandboxId;
  paths.sandboxDir = fs::path(std::string(SANDBOXES_DIRECTORY_PATH)) / sandboxId;
  paths.sandboxVmxRaw = (paths.sandboxDir / (sandboxId + ".vmx")).string();
  paths.sandboxVmx = Utills::ensureQuoted(paths.sandboxVmxRaw);
  paths.hostShared = paths.sandboxDir / "shared";
  return paths;
}

std::vector<std::string> buildWarmSandboxIds() {
  std::vector<std::string> sandboxIds;
  sandboxIds.reserve(WARM_SANDBOX_COUNT);
  for (unsigned int i = 0; i < WARM_SANDBOX_COUNT; ++i) {
    sandboxIds.push_back(std::format("{}-{:02}", WARM_SANDBOX_PREFIX, i + 1));
  }
  return sandboxIds;
}

fs::path warmStateFilePath(const std::string &sandboxId) {
  return buildSandboxPaths(sandboxId).sandboxDir / std::string(WARM_STATE_FILE_NAME);
}

WarmSandboxState readWarmSandboxState(const std::string &sandboxId,
                                      std::string *detail = nullptr) {
  if (detail != nullptr) {
    detail->clear();
  }

  const fs::path statePath = warmStateFilePath(sandboxId);
  if (!fs::exists(statePath)) {
    return WarmSandboxState::Cold;
  }

  std::ifstream in(statePath);
  std::string line;
  std::getline(in, line);

  if (line.rfind("busy:", 0) == 0) {
    if (detail != nullptr) {
      *detail = line.substr(5);
    }
    return WarmSandboxState::Busy;
  }
  if (line == "preparing") {
    return WarmSandboxState::Preparing;
  }
  if (line == "ready") {
    return WarmSandboxState::Ready;
  }
  if (line == "failed") {
    return WarmSandboxState::Failed;
  }
  return WarmSandboxState::Cold;
}

bool writeWarmSandboxState(const std::string &sandboxId,
                           WarmSandboxState state,
                           std::string_view detail = {}) {
  const fs::path statePath = warmStateFilePath(sandboxId);
  std::error_code ec;
  fs::create_directories(statePath.parent_path(), ec);
  if (ec) {
    return false;
  }

  if (state == WarmSandboxState::Cold) {
    fs::remove(statePath, ec);
    return true;
  }

  std::ofstream out(statePath, std::ios::trunc);
  if (!out) {
    return false;
  }

  switch (state) {
  case WarmSandboxState::Preparing:
    out << "preparing";
    break;
  case WarmSandboxState::Ready:
    out << "ready";
    break;
  case WarmSandboxState::Busy:
    out << "busy:" << detail;
    break;
  case WarmSandboxState::Failed:
    out << "failed";
    break;
  case WarmSandboxState::Cold:
    break;
  }

  return static_cast<bool>(out);
}

std::optional<std::string> claimReadyWarmSandbox(const fs::path &poolRoot,
                                                 const std::string &scanId) {
  for (const auto &sandboxId : buildWarmSandboxIds()) {
    auto lock = SandboxLock::tryAcquire(poolRoot, sandboxId);
    if (!lock.has_value()) {
      continue;
    }

    if (readWarmSandboxState(sandboxId) != WarmSandboxState::Ready) {
      continue;
    }

    if (!writeWarmSandboxState(sandboxId, WarmSandboxState::Busy, scanId)) {
      continue;
    }

    return sandboxId;
  }

  return std::nullopt;
}

void markWarmSandboxState(const fs::path &poolRoot,
                          const std::string &sandboxId,
                          WarmSandboxState state,
                          std::string_view detail = {}) {
  if (auto lock = SandboxLock::tryAcquire(poolRoot, sandboxId); lock.has_value()) {
    (void)writeWarmSandboxState(sandboxId, state, detail);
  }
}

bool ensureDirectory(const fs::path &path, std::string_view label) {
  std::error_code ec;
  fs::create_directories(path, ec);
  if (ec) {
    std::cerr << "\tFAIL create " << label << " '" << path.string()
              << "': " << ec.message() << std::endl;
    return false;
  }
  return true;
}

bool stopSandboxIfRunning(const std::string &vmRunPath,
                          const SandboxPaths &paths) {
  const auto powerState = Utills::getVmPowerState(vmRunPath, paths.sandboxVmx);
  if (powerState != Utills::VmPowerState::Running) {
    return true;
  }
  return Utills::closeVM(vmRunPath, paths.sandboxVmx, paths.sandboxId);
}

bool copyFileToGuest(const std::string &vmRunPath,
                     const std::string &sandboxVmx,
                     const std::string &hostPath,
                     const std::string &guestPath,
                     std::string_view label) {
  const std::string cmd = std::format(
      R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
      vmRunPath,
      std::string(GUEST_USER),
      std::string(GUEST_PASS),
      sandboxVmx,
      Utills::ensureQuoted(hostPath),
      Utills::ensureQuoted(guestPath));
  const int rc = Utills::executeAndWaitRC(cmd);
  if (rc != 0) {
    std::cerr << "\tFAIL copy " << label << " rc=" << rc << std::endl;
    return false;
  }
  return true;
}

bool ensureGuestSupportFile(const std::string &vmRunPath,
                            const std::string &sandboxVmx,
                            const std::string &hostPath,
                            const std::string &guestPath,
                            std::string_view label) {
  if (Utills::guestPathExists(vmRunPath, sandboxVmx, guestPath)) {
    return true;
  }
  return copyFileToGuest(vmRunPath, sandboxVmx, hostPath, guestPath, label);
}

bool prepareSandboxEnvironment(const std::string &vmRunPath,
                               const std::string &baseVmx,
                               const SandboxPaths &paths,
                               const std::string &guestWorkDir,
                               const std::string &sharedFolderName,
                               const std::string &pmHostAbs,
                               const std::string &guestPmPath,
                               const std::string &dllInjectorHostAbs,
                               const std::string &guestDllInjectorPath,
                               const std::string &processRunnerHostAbs,
                               const std::string &guestProcessRunnerPath) {
  if (!ensureDirectory(paths.hostShared, "host shared dir")) {
    return false;
  }

  std::cout << "[1.0/7] Clone linked VM if needed" << std::endl;
  {
    ScopedStepTimer timer("clone linked VM");
    if (!fs::exists(paths.sandboxVmxRaw)) {
      const std::string cmd = std::format(
          R"({} -T ws clone {} {} linked -cloneName={})",
          vmRunPath,
          baseVmx,
          paths.sandboxVmx,
          paths.sandboxId);

      const int rc = Utills::executeAndWaitRC(cmd);
      if (rc != 0) {
        std::cerr << "\tFAIL clone rc=" << rc << std::endl;
        return false;
      }
    }
  }

  std::cout << "[1.1/7] Start VM if needed" << std::endl;
  {
    ScopedStepTimer timer("start VM");
    const auto powerState = Utills::getVmPowerState(vmRunPath, paths.sandboxVmx);
    if (powerState != Utills::VmPowerState::Running) {
      const std::string cmd = std::format(
          R"({} -T ws start {} {})",
          vmRunPath,
          paths.sandboxVmx,
          VM_START_MODE);
      const int rc = Utills::executeAndWaitRC(cmd);
      if (rc != 0) {
        std::cerr << "\tFAIL start rc=" << rc << std::endl;
        return false;
      }
    }
  }

  std::cout << "[1.1.b/7] Configure Shared Folder" << std::endl;
  {
    ScopedStepTimer timer("configure shared folder");
    if (sharedFolderName.empty()) {
      std::cerr << "\tFAIL: could not derive shared folder name from GUEST_SHARED_DIR='"
                << GUEST_SHARED_DIR << "'" << std::endl;
      return false;
    }

    const std::string removeCmd = std::format(
        R"({} -T ws removeSharedFolder {} {})",
        vmRunPath,
        paths.sandboxVmx,
        sharedFolderName);
    (void)Utills::executeAndWaitRC(removeCmd);

    const std::string addCmd = std::format(
        R"({} -T ws addSharedFolder {} {} {})",
        vmRunPath,
        paths.sandboxVmx,
        sharedFolderName,
        Utills::ensureQuoted(paths.hostShared.string()));
    const int rc = Utills::executeAndWaitRC(addCmd);
    if (rc != 0) {
      std::cerr << "\tFAIL addSharedFolder rc=" << rc << std::endl;
      return false;
    }
  }

  std::cout << "[1.2/7] Wait for VMware Tools (" << VM_TOOLS_MAX_RETRIES
            << " retries x " << VM_TOOLS_SLEEP_MS << "ms)" << std::endl;
  {
    ScopedStepTimer timer("wait for VMware Tools");
    if (!Utills::waitForTools(
            vmRunPath,
            paths.sandboxVmx,
            static_cast<int>(VM_TOOLS_MAX_RETRIES),
            static_cast<int>(VM_TOOLS_SLEEP_MS))) {
      std::cerr << "\tFAIL: VMware Tools not ready" << std::endl;
      return false;
    }
  }

  std::cout << "[1.3/7] Enable shared folders in guest" << std::endl;
  {
    ScopedStepTimer timer("enable shared folders");
    const std::string enableCmd = std::format(
        R"({} -T ws enableSharedFolders {})",
        vmRunPath,
        paths.sandboxVmx);
    const int rc = Utills::executeAndWaitRC(enableCmd);
    if (rc != 0) {
      std::cerr << "\tWARN enableSharedFolders rc=" << rc
                << " (shared folders may already be enabled)" << std::endl;
    }

    const std::string checkCmd = std::format(
        R"({} -T ws -gu {} -gp {} directoryExistsInGuest {} {})",
        vmRunPath,
        std::string(GUEST_USER),
        std::string(GUEST_PASS),
        paths.sandboxVmx,
        Utills::ensureQuoted(std::string(GUEST_SHARED_DIR)));
    const int checkRc = Utills::executeAndWaitRC(checkCmd);
    if (checkRc != 0) {
      std::cerr << "\tFAIL: shared folder '" << GUEST_SHARED_DIR
                << "' is not accessible inside the guest (rc=" << checkRc << ")"
                << std::endl;
      return false;
    }
  }

  std::cout << "[2.0/7] Create guest work dir: " << guestWorkDir << std::endl;
  {
    ScopedStepTimer timer("create guest work dir");
    const std::string existsCmd = std::format(
        R"({} -T ws -gu {} -gp {} directoryExistsInGuest {} {})",
        vmRunPath,
        std::string(GUEST_USER),
        std::string(GUEST_PASS),
        paths.sandboxVmx,
        Utills::ensureQuoted(guestWorkDir));
    const int existsRc = Utills::executeAndWaitRC(existsCmd);
    if (existsRc != 0) {
      const std::string createCmd = std::format(
          R"({} -T ws -gu {} -gp {} createDirectoryInGuest {} {})",
          vmRunPath,
          std::string(GUEST_USER),
          std::string(GUEST_PASS),
          paths.sandboxVmx,
          Utills::ensureQuoted(guestWorkDir));
      const int createRc = Utills::executeAndWaitRC(createCmd);
      if (createRc != 0) {
        std::cerr << "\tFAIL createDirectory rc=" << createRc
                  << " (directory does not exist and cannot be created)"
                  << std::endl;
        return false;
      }
    }
  }

  std::cout << "[2.1/7] Ensure monitor exists in guest" << std::endl;
  {
    ScopedStepTimer timer("ensure monitor");
    if (!ensureGuestSupportFile(
            vmRunPath, paths.sandboxVmx, pmHostAbs, guestPmPath, "monitor")) {
      return false;
    }
  }

  std::cout << "[2.2/7] Ensure DLL injector exists in guest" << std::endl;
  {
    ScopedStepTimer timer("ensure DLL injector");
    if (!ensureGuestSupportFile(
            vmRunPath,
            paths.sandboxVmx,
            dllInjectorHostAbs,
            guestDllInjectorPath,
            "DLL injector")) {
      return false;
    }
  }

  std::cout << "[2.3/7] Ensure process runner exists in guest" << std::endl;
  {
    ScopedStepTimer timer("ensure process runner");
    if (!ensureGuestSupportFile(
            vmRunPath,
            paths.sandboxVmx,
            processRunnerHostAbs,
            guestProcessRunnerPath,
            "process runner")) {
      return false;
    }
  }

  return true;
}

bool copyWarmSandboxResult(const std::string &scanId,
                           const std::string &sandboxId,
                           const fs::path &hostLogPath) {
  if (scanId == sandboxId) {
    return true;
  }

  const fs::path targetSharedDir =
      fs::path(std::string(SANDBOXES_DIRECTORY_PATH)) / scanId / "shared";
  if (!ensureDirectory(targetSharedDir, "scan result dir")) {
    return false;
  }

  std::error_code ec;
  fs::copy_file(
      hostLogPath,
      targetSharedDir / fs::path(std::string(SHARE_FILE_NAME)),
      fs::copy_options::overwrite_existing,
      ec);
  if (ec) {
    std::cerr << "\tFAIL copy result log to scan dir: " << ec.message()
              << std::endl;
    return false;
  }
  return true;
}

bool prepareWarmSandbox(const std::string &sandboxId) {
  const auto vmRunPath = std::string(VM_RUN_PATH);
  const auto baseVmx = std::string(ANALYSIS_VM_PATH);
  const auto guestWorkDir = std::string(SUSPICIOUS_WORKDIR_GUEST);

  fs::path guestSharedPath(GUEST_SHARED_DIR);
  guestSharedPath = guestSharedPath.lexically_normal();
  const std::string sharedFolderName = guestSharedPath.filename().string();

  const std::string pmHostAbs =
      fs::absolute(std::string(PM_FILE_PATH)).string();
  const std::string dllInjectorHostAbs =
      fs::absolute(std::string(DLL_INJECTOR_FILE_PATH)).string();
  const std::string processRunnerHostAbs =
      fs::absolute(std::string(PROCCES_RUNNER_FILE_PATH)).string();

  const auto guestPmPath = std::string(PM_FILE_PATH_GUEST);
  const auto guestDllInjectorPath = std::string(DLL_INJECTOR_FILE_PATH_GUEST);
  const auto guestProcessRunnerPath = std::string(PROCCES_RUNNER_FILE_PATH_GUEST);

  const SandboxPaths paths = buildSandboxPaths(sandboxId);

  std::cout << "[warmup] Preparing sandbox " << sandboxId << std::endl;
  {
    ScopedStepTimer timer("reset warm sandbox");
    if (!stopSandboxIfRunning(vmRunPath, paths)) {
      return false;
    }

    std::error_code ec;
    fs::remove_all(paths.sandboxDir, ec);
    if (ec) {
      std::cerr << "\tFAIL remove sandbox dir '" << paths.sandboxDir.string()
                << "': " << ec.message() << std::endl;
      return false;
    }
  }

  return prepareSandboxEnvironment(
      vmRunPath,
      baseVmx,
      paths,
      guestWorkDir,
      sharedFolderName,
      pmHostAbs,
      guestPmPath,
      dllInjectorHostAbs,
      guestDllInjectorPath,
      processRunnerHostAbs,
      guestProcessRunnerPath);
}

int prepareWarmPool() {
  if (WARM_SANDBOX_COUNT == 0) {
    std::cout << "[warmup] Warm sandbox pool disabled" << std::endl;
    return EXIT_SUCCESS;
  }

  const fs::path poolRoot = fs::path(std::string(SANDBOXES_DIRECTORY_PATH));
  bool allSucceeded = true;

  for (const auto &sandboxId : buildWarmSandboxIds()) {
    auto lock = SandboxLock::tryAcquire(poolRoot, sandboxId);
    if (!lock.has_value()) {
      std::cout << "[warmup] Skip " << sandboxId
                << " because another workflow already owns it" << std::endl;
      continue;
    }

    const auto currentState = readWarmSandboxState(sandboxId);
    if (currentState == WarmSandboxState::Busy ||
        currentState == WarmSandboxState::Preparing) {
      std::cout << "[warmup] Skip " << sandboxId
                << " because it is not currently available" << std::endl;
      continue;
    }

    if (!writeWarmSandboxState(sandboxId, WarmSandboxState::Preparing)) {
      std::cerr << "[warmup] Failed to mark " << sandboxId
                << " as preparing" << std::endl;
      allSucceeded = false;
      continue;
    }

    lock.reset();

    const bool prepared = prepareWarmSandbox(sandboxId);
    markWarmSandboxState(
        poolRoot,
        sandboxId,
        prepared ? WarmSandboxState::Ready : WarmSandboxState::Failed);
    allSucceeded &= prepared;
  }

  return allSucceeded ? EXIT_SUCCESS : EXIT_FAILURE;
}

int runScan(const std::string &scanId,
            const fs::path &suspiciousHostPath,
            int runTimeSec) {
  const auto vmRunPath = std::string(VM_RUN_PATH);
  const auto baseVmx = std::string(ANALYSIS_VM_PATH);
  const auto poolRoot = fs::path(std::string(SANDBOXES_DIRECTORY_PATH));

  fs::path guestSharedPath(GUEST_SHARED_DIR);
  guestSharedPath = guestSharedPath.lexically_normal();
  const std::string sharedFolderName = guestSharedPath.filename().string();

  const auto guestWorkDir = std::string(SUSPICIOUS_WORKDIR_GUEST);
  const auto guestPmPath = std::string(PM_FILE_PATH_GUEST);
  const auto guestDllInjectorPath = std::string(DLL_INJECTOR_FILE_PATH_GUEST);
  const auto guestProcessRunnerPath = std::string(PROCCES_RUNNER_FILE_PATH_GUEST);

  const std::string pmHostAbs =
      fs::absolute(std::string(PM_FILE_PATH)).string();
  const std::string dllInjectorHostAbs =
      fs::absolute(std::string(DLL_INJECTOR_FILE_PATH)).string();
  const std::string processRunnerHostAbs =
      fs::absolute(std::string(PROCCES_RUNNER_FILE_PATH)).string();
  const std::string suspiciousHostAbs =
      fs::absolute(suspiciousHostPath).string();

  const std::optional<std::string> warmSandboxId =
      claimReadyWarmSandbox(poolRoot, scanId);
  const std::string sandboxId =
      warmSandboxId.has_value() ? *warmSandboxId : scanId;
  const bool usedWarmSandbox = warmSandboxId.has_value();

  const SandboxPaths paths = buildSandboxPaths(sandboxId);
  const std::string guestSuspectedFilePath =
      (fs::path(guestWorkDir) /
       (scanId + "_" + suspiciousHostPath.filename().string()))
          .string();
  const std::string guestLogPath =
      (fs::path(GUEST_SHARED_DIR) / fs::path(std::string(SHARE_FILE_NAME))).string();
  const fs::path hostLogPath = paths.hostShared / fs::path(std::string(SHARE_FILE_NAME));

  std::cout << (usedWarmSandbox ? "[pool] Using ready warm sandbox: "
                                : "[pool] No ready warm sandbox, using dedicated sandbox: ")
            << sandboxId << std::endl;

  const auto totalStart = std::chrono::steady_clock::now();

  auto failRun = [&](std::string_view message) -> int {
    std::cerr << message << std::endl;
    (void)stopSandboxIfRunning(vmRunPath, paths);
    if (usedWarmSandbox) {
      markWarmSandboxState(poolRoot, sandboxId, WarmSandboxState::Failed);
    }
    return EXIT_FAILURE;
  };

  if (!prepareSandboxEnvironment(
          vmRunPath,
          baseVmx,
          paths,
          guestWorkDir,
          sharedFolderName,
          pmHostAbs,
          guestPmPath,
          dllInjectorHostAbs,
          guestDllInjectorPath,
          processRunnerHostAbs,
          guestProcessRunnerPath)) {
    return failRun("\tFAIL prepare sandbox environment");
  }

  {
    ScopedStepTimer timer("clean previous shared log");
    std::error_code ec;
    fs::remove(hostLogPath, ec);
  }

  std::cout << "[2.4/7] Copy suspicious -> guest" << std::endl;
  {
    ScopedStepTimer timer("copy suspicious payload");
    if (!copyFileToGuest(
            vmRunPath,
            paths.sandboxVmx,
            suspiciousHostAbs,
            guestSuspectedFilePath,
            "payload")) {
      return failRun("\tFAIL copy payload");
    }
  }

  std::cout << "[3.0/7] Start monitor in guest" << std::endl;
  {
    ScopedStepTimer timer("start monitor");
    const std::string cmd = std::format(
        R"({} -T ws -gu {} -gp {} runProgramInGuest {} -noWait {} {} {}{})",
        vmRunPath,
        std::string(GUEST_USER),
        std::string(GUEST_PASS),
        paths.sandboxVmx,
        Utills::ensureQuoted(guestPmPath),
        Utills::ensureQuoted(guestSuspectedFilePath),
        Utills::ensureQuoted(guestLogPath),
        (runTimeSec > 0 ? std::format(" {}", runTimeSec) : std::string{}));
    const int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      return failRun(std::format("\tFAIL run monitor rc={}", rc));
    }
  }

  std::cout << "[3.1/7] Start Process Runner in guest" << std::endl;
  {
    ScopedStepTimer timer("start process runner");
    const std::string cmd = std::format(
        R"({} -T ws -gu {} -gp {} runProgramInGuest {} -noWait {} {} {} {})",
        vmRunPath,
        std::string(GUEST_USER),
        std::string(GUEST_PASS),
        paths.sandboxVmx,
        Utills::ensureQuoted(guestProcessRunnerPath),
        Utills::ensureQuoted(guestSuspectedFilePath),
        Utills::ensureQuoted(guestDllInjectorPath),
        Utills::ensureQuoted(guestWorkDir));
    const int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      return failRun(std::format("\tFAIL run payload rc={}", rc));
    }
  }

  std::cout << "[4/7] Let payload run for " << runTimeSec << "s" << std::endl;
  {
    ScopedStepTimer timer("payload runtime window");
    std::this_thread::sleep_for(std::chrono::seconds(runTimeSec));
  }

  std::cout << "[5/7] Verify shared log availability" << std::endl;
  {
    ScopedStepTimer timer("verify shared log availability");
    std::cout << "\tExpected guest DB path: " << guestLogPath << std::endl;
    std::cout << "\tExpected host  DB path: " << hostLogPath.string() << std::endl;

    if (!fs::exists(hostLogPath)) {
      return failRun(std::format(
          "\tWARN: DB file NOT found on host path: {}",
          hostLogPath.string()));
    }
  }

  if (!copyWarmSandboxResult(scanId, sandboxId, hostLogPath)) {
    return failRun("\tFAIL copy result log");
  }

  std::cout << "[6/7] Shutdown VM" << std::endl;
  {
    ScopedStepTimer timer("shutdown VM");
    if (!stopSandboxIfRunning(vmRunPath, paths)) {
      return failRun("\tFAIL stop VM");
    }
  }

  if (usedWarmSandbox) {
    markWarmSandboxState(poolRoot, sandboxId, WarmSandboxState::Cold);
  }

  const auto totalElapsedMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - totalStart);
  std::cout << "[7/7] Total VM workflow time: "
            << totalElapsedMs.count() << "ms" << std::endl;
  std::cout << "Done." << std::endl;
  Utills::printBanner(true);
  return EXIT_SUCCESS;
}

} // namespace

int main(int argc, char *argv[]) {
  if (argc == 2 && std::string_view(argv[1]) == "--self-test") {
    return runSelfTests();
  }

  if (argc == 2 && std::string_view(argv[1]) == "--prepare-warm-pool") {
    return prepareWarmPool();
  }

  if (argc == 3 && std::string_view(argv[1]) == "--prepare") {
    const fs::path poolRoot = fs::path(std::string(SANDBOXES_DIRECTORY_PATH));
    const std::string sandboxId(argv[2]);
    markWarmSandboxState(poolRoot, sandboxId, WarmSandboxState::Preparing);
    const bool prepared = prepareWarmSandbox(sandboxId);
    markWarmSandboxState(
        poolRoot,
        sandboxId,
        prepared ? WarmSandboxState::Ready : WarmSandboxState::Failed);
    return prepared ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  if (argc < 3 || argc > 4) {
    std::cerr << "Usage: " << argv[0]
              << " <scan_id> <virus_path> [runTime]\n"
              << "       " << argv[0] << " --prepare <sandbox_id>\n"
              << "       " << argv[0] << " --prepare-warm-pool" << std::endl;
    return EXIT_FAILURE;
  }

  const std::string scanId(argv[1]);
  const fs::path suspiciousHostPath(argv[2]);
  const int runTimeSec = (argc == 4) ? std::atoi(argv[3]) : DEFUALT_TIME_CHECK;

  return runScan(scanId, suspiciousHostPath, runTimeSec);
}
