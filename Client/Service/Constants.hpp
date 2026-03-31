#define NOMINMAX
#include <windows.h>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace Constants {
constexpr unsigned int SLEEP_BETWEEN_NO_NOTIFICATIONS_MS = 1000 / 8;
constexpr size_t BYTES_PER_KIB = 1024;
constexpr size_t BYTES_PER_MIB = BYTES_PER_KIB * BYTES_PER_KIB;
const std::vector<std::string> YARA_RULES_FILES = {
    "aaa.yrc",
};
constexpr double ENTROPY_THRESHOLD = 7.0;
constexpr unsigned int ALPHABET_SIZE = 256;
constexpr unsigned int IDLE_SLEEP_TIME_MS = 1000;
constexpr size_t YARA_CHUNK_SIZE = BYTES_PER_MIB;
constexpr size_t SHA256_BUFFER_SIZE = BYTES_PER_MIB;
constexpr std::wstring_view AYDO_DRIVER_DEVICE_PATH = LR"(\\.\AydoDriver)";
constexpr std::string_view HASHES_DB_PATH = "file_hashes.db";
constexpr std::string_view SERVER_URL = "http://127.0.0.1";
constexpr int DYNAMIC_SCAN_POLL_INTERVAL = 5;
constexpr DWORD DYNAMIC_SCAN_MAX_WAIT_MS = 2000;
constexpr DWORD DYNAMIC_SCAN_RESULT_WAIT_BUFFER_MS = 5000;
constexpr DWORD DYNAMIC_SCAN_MIN_WAIT_MS = 2000;
constexpr DWORD DYNAMIC_SCAN_CLIENT_POLL_MS = 200;
constexpr std::chrono::milliseconds SERVER_REACHABILITY_POLL_INTERVAL{std::chrono::seconds{5}};
constexpr std::string_view AYDO_GUI_PIPE_NAME = R"(\\.\pipe\AydoServicePipe)";
constexpr int YARA_INFO_MATCH_THRESHOLD = 20;
constexpr size_t PIPE_BUFFER_SIZE = 65536;
constexpr DWORD PIPE_TIMEOUT_MS = 1000;
constexpr DWORD MAX_UNICODE_PATH_CHARS = 32767;
constexpr size_t PSAPI_PATH_RESERVE_MULTIPLIER = 8;
constexpr DWORD DOS_DEVICE_TARGET_BUF_CHARS = 1024;
constexpr DWORD DRIVE_STRINGS_BUF_CHARS = 512;
constexpr std::string_view QUARANTINE_DIR_NAME = "quarantine";
constexpr std::string_view QUARANTINE_EXTENSION = ".bad";
constexpr int INFECTED_FILE_ACTION_QUARANTINE = 1;
constexpr int INFECTED_FILE_ACTION_DELETE = 2;
constexpr int SCAN_PROGRESS_PERCENTAGE_MAX = 100;
constexpr std::chrono::milliseconds REQUEST_TIMEOUT_DURATION{std::chrono::seconds{2}};
constexpr int SLOW_SCAN_RESUME_TIMEOUT_S = 15;
}; // namespace Constants
