#include "SCAScanningEngine.hpp"

#include <botan/hex.h>
#include <fstream>

// Helper to convert hex strings to byte vectors for Aho-Corasick
static std::vector<std::vector<uint8_t>> hexStringsToBytePatterns(const std::vector<std::string> &hexPatterns) {
  std::vector<std::vector<uint8_t>> patterns;
  patterns.reserve(hexPatterns.size());

  for (const auto &hex : hexPatterns) {
    // Botan::hex_decode may return std::vector<uint8_t> or secure_vector<uint8_t>
    // Use the std::vector overload; ignore whitespace in patterns if present.
    auto bytes = Botan::hex_decode(hex, true /*ignore_ws*/);
    patterns.emplace_back(bytes.begin(), bytes.end());
  }

  return patterns;
}

SCAScanningEngine::SCAScanningEngine(const std::vector<std::string> &hexPatterns)
    : m_ahoCorasick(hexStringsToBytePatterns(hexPatterns), true) {}

SearchResult SCAScanningEngine::scanFile(const std::string &filePath) {
  std::ifstream file(filePath, std::ios::binary);
  if (!file) {
    return std::nullopt;
  }

  std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());

  return scanMemory(data);
}

SearchResult SCAScanningEngine::scanMemory(const std::vector<uint8_t> &data) {
  auto result = m_ahoCorasick.search(data);

  if (result.empty()) {
    return std::nullopt;
  }

  const auto &firstMatch = result[0];
  const char *begin = reinterpret_cast<const char *>(data.data() + firstMatch.startPos);
  const size_t length = firstMatch.endPos - firstMatch.startPos + 1;

  return std::string(begin, begin + length);
}
