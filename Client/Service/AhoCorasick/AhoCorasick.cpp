#include "AhoCorasick.hpp"

#include <queue>

AhoCorasick::AhoCorasick(const std::vector<std::vector<uint8_t>> &patterns, bool quitOnFirstMatch)
    : m_patterns(patterns)
    , m_quitOnFirstMatch(quitOnFirstMatch) {
  m_root = std::make_shared<ACNode>();
  _buildTrie();
  _buildFailureLinks();
}

void AhoCorasick::_buildTrie() {
  for (size_t i = 0; i < m_patterns.size(); i++) {
    std::shared_ptr<ACNode> node = m_root;

    for (uint8_t c : m_patterns[i]) {
      if (node->children.find(c) == node->children.end()) {
        node->children[c] = std::make_shared<ACNode>();
      }

      node = node->children[c];
    }

    node->output.push_back(i);
  }
}

void AhoCorasick::_buildFailureLinks() {
  // Initialize queue for BFS traversal of the trie
  std::queue<std::shared_ptr<ACNode>> q;

  // Set failure links for root's direct children to point back to root
  // and add them to the queue for processing
  for (auto &child : m_root->children) {
    child.second->fail = m_root;
    q.push(child.second);
  }

  // Process nodes in BFS order to build failure links
  while (!q.empty()) {
    std::shared_ptr<ACNode> node = q.front();
    q.pop();

    // Process each child of the current node
    for (auto &child : node->children) {
      q.push(child.second);

      // Find the appropriate failure link for this child
      // by traversing up the failure chain
      std::shared_ptr<ACNode> fail_node = node->fail;
      while (fail_node && fail_node->children.find(child.first) == fail_node->children.end()) {
        fail_node = fail_node->fail;
      }

      // Set the failure link to the longest proper suffix
      // that exists in the trie, or to root if none found
      if (fail_node && fail_node->children.find(child.first) != fail_node->children.end()) {
        child.second->fail = fail_node->children[child.first];
      } else {
        child.second->fail = m_root;
      }

      // Merge output patterns from the failure node
      // to ensure all matches are found during search
      for (size_t idx : child.second->fail->output) {
        child.second->output.push_back(idx);
      }
    }
  }
}

// We don't use vectors here because it's slower than raw arrays
std::vector<AhoCorasick::Match> AhoCorasick::search(const uint8_t *data, size_t length) const {
  std::vector<AhoCorasick::Match> matches;
  std::shared_ptr<ACNode> node = m_root;

  for (size_t i = 0; i < length; i++) {
    uint8_t byte = data[i];

    while (node && node->children.find(byte) == node->children.end()) {
      node = node->fail;
    }

    if (!node) {
      node = m_root;
    } else {
      node = node->children.find(byte)->second;
    }

    if (!node->output.empty()) {
      for (size_t patternIndex : node->output) {
        const size_t patternLength = m_patterns[patternIndex].size();
        if (patternLength == 0 || patternLength > i + 1) {
          continue;
        }

        matches.push_back(Match{
            .patternIndex = patternIndex,
            .startPos = i + 1 - patternLength,
            .endPos = i});
        if (m_quitOnFirstMatch) {
          return matches;
        }
      }
    }
  }

  return matches;
}
