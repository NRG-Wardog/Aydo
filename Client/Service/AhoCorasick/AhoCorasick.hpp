#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ACNode.hpp"

class AhoCorasick {
private:
  std::shared_ptr<ACNode> m_root;
  std::vector<std::vector<uint8_t>> m_patterns;
  bool m_quitOnFirstMatch;

public:
  struct Match {
    size_t patternIndex;
    size_t startPos;
    size_t endPos;
  };

  explicit AhoCorasick(const std::vector<std::vector<uint8_t>> &patterns, bool quitOnFirstMatch = false);

  [[nodiscard]] std::vector<Match> search(const std::vector<uint8_t> &text) const {
    return search(text.data(), text.size());
  }

  [[nodiscard]] std::vector<Match> search(const uint8_t *data, size_t length) const;

private:
  void _buildTrie();
  void _buildFailureLinks();
};
