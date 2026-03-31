#pragma once

#include <array>
#include <string_view>

namespace Constants {
constexpr std::string_view CONFIG_FILE = "config.json";
constexpr std::string_view JWT_SECRET_JSON_KEY = "jwtSecret";
constexpr std::string_view PROCESSING_CRON_INTERVAL_KEY =
    "processingCronIntervalSeconds";

// Authentication - JWT Token TTLs
constexpr long long ACCESS_TOKEN_TTL_SECONDS = 15 * 60;              // 15 minutes
constexpr long long REFRESH_TOKEN_TTL_SECONDS = 30LL * 24 * 60 * 60; // 30 days

// Password Hashing - Argon2id Parameters
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
constexpr size_t ARGON2_PARALLELISM = 1;
constexpr size_t ARGON2_MEMORY_KB = 1024 * 46;
constexpr size_t ARGON2_ITERATIONS = 1;

// File Upload
constexpr std::string_view UPLOADS_DIRECTORY = "uploads";
constexpr std::string_view MAX_UPLOAD_BYTES_KEY = "maxUploadBytes";

// VMRunner
constexpr std::string_view VMRUNNER_PATH = R"(C:\Dev\Magshii\Project\DDDDDDDD\aydo\x64\Release\VMRunner.exe)";
constexpr std::string_view SANDBOXES_DIRECTORY_PATH = R"(D:\veeeertoooaaalll)";

constexpr double DEFAULT_SCAN_CHECK_INTERVAL_S = 5.0;

inline constexpr std::array<const char *, 1> SIGMA_QUERY_PATHS = {
    R"(C:\Dev\Magshii\Project\DDDDDDDD\aydo\data\sigma_queries.json)",
};

constexpr int RETRY_SCAN_IF_FAILED_SECONDS = 300;

} // namespace Constants
