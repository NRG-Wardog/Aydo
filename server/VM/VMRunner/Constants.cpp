#include "Constants.hpp"

#include <cstdlib>
#include <limits>

std::string getEnvOrDefault(const char *name, std::string_view def) {
  if (const char *v = std::getenv(name)) {
    return std::string(v);
  }
  return std::string(def);
}

static unsigned int getEnvUIntOrDefault(const char *name, unsigned int def) {
  if (const char *v = std::getenv(name)) {
    char *end = nullptr;
    const unsigned long parsed = std::strtoul(v, &end, 10);
    if (end != v && *end == '\0' &&
        parsed <= std::numeric_limits<unsigned int>::max()) {
      return static_cast<unsigned int>(parsed);
    }
  }
  return def;
}

const std::string VM_RUN_PATH =
    getEnvOrDefault("VM_RUN_PATH", R"(C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe)");

const std::string ANALYSIS_VM_PATH =
    getEnvOrDefault("ANALYSIS_VM_PATH", R"(D:\veeeertoooaaalll\SANDBOX1\SANDBOX1.vmx)");

const std::string SANDBOXES_DIRECTORY_PATH =
    getEnvOrDefault("SANDBOXES_DIRECTORY_PATH", R"(D:\veeeertoooaaalll\)");

const std::string VM_START_MODE =
    getEnvOrDefault("VM_START_MODE", "nogui");

const std::string PM_FILE_PATH_GUEST =
    getEnvOrDefault("PM_FILE_PATH_GUEST",
                    R"(C:\Users\KAN12\Desktop\ProcessMonitor.exe)");

const std::string DLL_INJECTOR_FILE_PATH_GUEST =
    getEnvOrDefault("DLL_INJECTOR_FILE_PATH_GUEST",
                    R"(C:\Users\KAN12\Desktop\InjectedDLL.dll)");

const std::string PROCCES_RUNNER_FILE_PATH_GUEST =
    getEnvOrDefault("PROCCES_RUNNER_FILE_PATH_GUEST",
                    R"(C:\Users\KAN12\Desktop\ProcessRunner.exe)");

const std::string HOST_FOLDER_PATH =
    getEnvOrDefault("HOST_FOLDER_PATH", R"(D:\Shared)");

const std::string SHARE_FILE_NAME =
    getEnvOrDefault("SHARE_FILE_NAME", "log.sqlite");

const std::string GUEST_SHARED_DIR =
    getEnvOrDefault("GUEST_SHARED_DIR",
                    R"(\\vmware-host\Shared Folders\Shared)");

const std::string GUEST_USER =
    getEnvOrDefault("GUEST_USER", "KAN12");

const std::string GUEST_PASS =
    getEnvOrDefault("GUEST_PASS", "1234");

const std::string PM_FILE_PATH =
    getEnvOrDefault("PM_FILE_PATH",
                    R"(C:\Dev\Magshii\Project\CCCCCCCCCC\aydo\server\VM\ProcessMonitor\bin\x64\Release\ProcessMonitor.exe)");

const std::string DLL_INJECTOR_FILE_PATH =
    getEnvOrDefault("DLL_INJECTOR_FILE_PATH",
                    R"(C:\Dev\Magshii\Project\CCCCCCCCCC\aydo\x64\Debug\ProcessRunnerDLL.dll)");

const std::string PROCCES_RUNNER_FILE_PATH =
    getEnvOrDefault("PROCCES_RUNNER_FILE_PATH",
                    R"(C:\Dev\Magshii\Project\CCCCCCCCCC\aydo\x64\Debug\ProcessRunner.exe)");

const std::string SUSPICIOUS_FILE_NAME_GUEST =
    getEnvOrDefault("SUSPICIOUS_FILE_NAME_GUEST",
                    "filetoplot.exe");

const std::string SUSPICIOUS_WORKDIR_GUEST =
    getEnvOrDefault("SUSPICIOUS_WORKDIR_GUEST",
                    R"(C:\Users\KAN12\Desktop\checks)");

const unsigned int VM_TOOLS_MAX_RETRIES =
    getEnvUIntOrDefault("VM_TOOLS_MAX_RETRIES", 60);

const unsigned int VM_TOOLS_SLEEP_MS =
    getEnvUIntOrDefault("VM_TOOLS_SLEEP_MS", 5000);

const unsigned int VM_SHUTDOWN_GRACE_MS =
    getEnvUIntOrDefault("VM_SHUTDOWN_GRACE_MS", 5000);
