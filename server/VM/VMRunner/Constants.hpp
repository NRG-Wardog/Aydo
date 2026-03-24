#pragma once
#include <cstdlib>
#include <string>
#include <string_view>

constexpr std::string_view BANNER = R"(
    ___             __    
   /   | __  ______/ /___ 
  / /| |/ / / / __  / __ \
 / ___ / /_/ / /_/ / /_/ /
/_/  |_\__, /\__,_/\____/ 
      /____/              
)";

std::string getEnvOrDefault(const char *name, std::string_view def);

extern const std::string VM_RUN_PATH;
extern const std::string ANALYSIS_VM_PATH;
extern const std::string SANDBOXES_DIRECTORY_PATH;
extern const std::string VM_START_MODE;
extern const std::string HOST_FOLDER_PATH;
extern const std::string SHARE_FILE_NAME;
extern const std::string GUEST_USER;
extern const std::string GUEST_PASS;
extern const std::string PM_FILE_PATH;
extern const std::string PM_FILE_PATH_GUEST;
extern const std::string DLL_INJECTOR_FILE_PATH;
extern const std::string PROCCES_RUNNER_FILE_PATH;
extern const std::string SUSPICIOUS_FILE_NAME_GUEST;
extern const std::string PROCCES_RUNNER_FILE_PATH_GUEST;
extern const std::string DLL_INJECTOR_FILE_PATH_GUEST;
extern const std::string SUSPICIOUS_WORKDIR_GUEST;
extern const std::string GUEST_SHARED_DIR;
extern const unsigned int VM_TOOLS_MAX_RETRIES;
extern const unsigned int VM_TOOLS_SLEEP_MS;
extern const unsigned int VM_SHUTDOWN_GRACE_MS;
extern const std::string WARM_SANDBOX_PREFIX;
extern const unsigned int WARM_SANDBOX_COUNT;
/*
 * Path in BOTH
 */
constexpr std::string_view SHARED_FOLDER_NAME = "shared";
/*-------------------------------------------------------------------------------------------*/
constexpr unsigned int ANIMATION_SLEEP_TIME_MS = 50;
constexpr unsigned int ANIMATION_SLEEP_TIME_S = 5;
constexpr unsigned int BOOTUP_SLEEP_TIME_S = 20;
constexpr unsigned int DEFUALT_TIME_CHECK = 60;
constexpr unsigned int STEPS_INTERVAL_S = 5;
