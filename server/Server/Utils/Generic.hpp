#pragma once

#include <string>

namespace Utils::Generic {

/**
 * @brief Get current Unix timestamp in seconds since epoch
 * @return Current Unix timestamp as long long
 */
[[nodiscard]] long long getCurrentTimestamp();
[[nodiscard]] std::string getScanSavePathForFileHash(const std::string &fileHash);

} // namespace Utils::Generic
