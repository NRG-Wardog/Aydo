#pragma once

#include <string_view>

namespace Constants {
constexpr std::string_view CONFIG_FILE = "config.json";
constexpr std::string_view JWT_SECRET_JSON_KEY = "jwtSecret";
constexpr std::string_view UPLOADS_DIR = "uploads";
constexpr std::string_view DEFAULT_VM_RUNNER_PATH = "server/VM/VMRunner/x64/Release/VMRunner.exe";

// Authentication - JWT Token TTLs
constexpr long long ACCESS_TOKEN_TTL_SECONDS = 15 * 60;              // 15 minutes
constexpr long long REFRESH_TOKEN_TTL_SECONDS = 30LL * 24 * 60 * 60; // 30 days
constexpr long long VM_START_BUFFER_S = 30;                          // Seconds to wait before querying VM

// Password Hashing - Argon2id Parameters
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
constexpr size_t ARGON2_PARALLELISM = 1;
constexpr size_t ARGON2_MEMORY_KB = 1024 * 46;
constexpr size_t ARGON2_ITERATIONS = 1;
} // namespace Constants
