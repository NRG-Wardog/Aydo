#include "Generic.hpp"

#include <chrono>

#include "../Constants.hpp"

namespace Utils::Generic {

long long getCurrentTimestamp() {
  const auto now = std::chrono::system_clock::now();
  const auto duration = now.time_since_epoch();

  return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

std::string getScanSavePathForFileHash(const std::string &fileHash) {
  std::string path = std::string(Constants::UPLOADS_DIR) + "/" + fileHash;

  return path;
}
} // namespace Utils::Generic
