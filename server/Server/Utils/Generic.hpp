#pragma once

#include <string>

namespace Utils::Generic {

[[nodiscard]] long long getCurrentTimestamp();

[[nodiscard]] std::string getScanSavePathForFileHash(const std::string &fileHash);

} // namespace Utils::Generic
