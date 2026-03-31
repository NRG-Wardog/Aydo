#include "YScanningEngine.hpp"

#include <fstream>
#include <ios>
#include <memory>

extern "C" {
#include "yara_x.h"
}

#include "../Constants.hpp"
#include "../Errors.hpp"

YScanningEngine::YScanningEngine(const std::vector<std::string> &compiledRulesFiles)
    : m_scoringSystem() {
  for (size_t i = 0; i < compiledRulesFiles.size(); ++i) {
    try {
      m_rulesSets.push_back(_loadCompiledRulesFromFile(compiledRulesFiles[i]));
    } catch (const std::exception &e) {
      throw;
    }
  }
}

YScanningEngine::YScanningEngine(const std::vector<std::string> &compiledRulesFiles, int killThreshold)
    : m_scoringSystem(killThreshold) {
  for (size_t i = 0; i < compiledRulesFiles.size(); ++i) {
    try {
      m_rulesSets.push_back(_loadCompiledRulesFromFile(compiledRulesFiles[i]));
    } catch (const std::exception &e) {
      throw;
    }
  }
}

std::shared_ptr<YRX_RULES> YScanningEngine::_loadCompiledRulesFromFile(const std::string &filePath) {
  std::ifstream file(filePath, std::ios::binary | std::ios::ate);

  if (!file.is_open()) {
    throw Errors::FailedToLoadCompiledRulesException("Failed to open file: " + filePath);
  }

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> buffer(size);
  if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
    throw Errors::FailedToLoadCompiledRulesException("Failed to read file: " + filePath);
  }

  YRX_RULES *rules_raw = nullptr;
  enum YRX_RESULT r = yrx_rules_deserialize(buffer.data(), buffer.size(), &rules_raw);
  if (r != YRX_SUCCESS || rules_raw == nullptr) {
    const char *err = yrx_last_error();
    std::string emsg = err ? err : "yrx_rules_deserialize failed";
    throw Errors::FailedToLoadCompiledRulesException("Failed to deserialize rules: " + emsg);
  }

  return {rules_raw, yrx_rules_destroy};
}

struct MatchCollector {
  std::vector<std::string> matches;
  std::atomic_bool found{false};
};

void YScanningEngine::_onMatchingRuleCallback(const struct YRX_RULE *rule, void *user_data) {
  if (!rule || !user_data) {
    return;
  }

  auto *collector = reinterpret_cast<MatchCollector *>(user_data);

  const uint8_t *ident = nullptr;
  size_t len = 0;
  if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS && ident && len > 0) {
    std::string ruleName(reinterpret_cast<const char *>(ident), len);
    collector->matches.emplace_back(ruleName);
  } else {
    collector->matches.emplace_back("unknown_rule");
  }

  collector->found.store(true, std::memory_order_relaxed);
}

std::vector<std::string> YScanningEngine::_scanMemoryInternal(const std::vector<uint8_t> &data) {
  if (m_rulesSets.empty()) {
    throw Errors::NoPatternsProvidedException();
  }

  MatchCollector collector;

  for (size_t ruleSetIdx = 0; ruleSetIdx < m_rulesSets.size(); ++ruleSetIdx) {
    const auto &rules_ptr = m_rulesSets[ruleSetIdx];

    if (!rules_ptr) {
      continue;
    }

    YRX_SCANNER *scanner = nullptr;
    if (yrx_scanner_create(rules_ptr.get(), &scanner) != YRX_SUCCESS || !scanner) {
      throw Errors::FailedToLoadCompiledRulesException("yrx_scanner_create failed");
    }

    if (yrx_scanner_on_matching_rule(scanner, _onMatchingRuleCallback, &collector) != YRX_SUCCESS) {
      yrx_scanner_destroy(scanner);
      throw Errors::FailedToLoadCompiledRulesException("yrx_scanner_on_matching_rule failed");
    }

    enum YRX_RESULT r = yrx_scanner_scan(scanner, data.data(), data.size());
    yrx_scanner_destroy(scanner);

    if (r != YRX_SUCCESS) {
      const char *err = yrx_last_error();
      std::string emsg = err ? err : "yrx_scanner_scan failed";
      throw Errors::FailedToLoadCompiledRulesException("Scan failed: " + emsg);
    }
  }

  return collector.matches;
}

std::vector<std::string> YScanningEngine::_scanFileInternal(const std::string &filePath) {
  std::ifstream ifs(filePath, std::ios::binary | std::ios::ate);
  if (!ifs) {
    throw Errors::FailedToLoadCompiledRulesException("Failed to open file for scanning: " + filePath);
  }

  std::streamsize size = ifs.tellg();
  if (size <= 0) {
    throw Errors::FailedToLoadCompiledRulesException("Invalid file size: " + filePath);
  }

  ifs.seekg(0, std::ios::beg);

  MatchCollector collector;

  using ScannerPtr = std::unique_ptr<YRX_SCANNER, decltype(&yrx_scanner_destroy)>;
  std::vector<ScannerPtr> scanners;
  scanners.reserve(m_rulesSets.size());

  for (const auto &rules_ptr : m_rulesSets) {
    if (!rules_ptr) {
      continue;
    }

    YRX_SCANNER *scanner_raw = nullptr;
    if (yrx_scanner_create(rules_ptr.get(), &scanner_raw) != YRX_SUCCESS || !scanner_raw) {
      throw Errors::FailedToLoadCompiledRulesException("yrx_scanner_create failed");
    }

    ScannerPtr scanner(scanner_raw, yrx_scanner_destroy);
    if (yrx_scanner_on_matching_rule(scanner.get(), _onMatchingRuleCallback, &collector) != YRX_SUCCESS) {
      throw Errors::FailedToLoadCompiledRulesException("yrx_scanner_on_matching_rule failed");
    }

    scanners.push_back(std::move(scanner));
  }

  if (scanners.empty()) {
    throw Errors::NoPatternsProvidedException();
  }

  std::vector<uint8_t> chunk(Constants::YARA_CHUNK_SIZE);

  while (ifs) {
    ifs.read(reinterpret_cast<char *>(chunk.data()), Constants::YARA_CHUNK_SIZE);
    const std::streamsize bytes_read = ifs.gcount();

    if (bytes_read <= 0) {
      break;
    }

    for (auto &scanner : scanners) {
      const enum YRX_RESULT r = yrx_scanner_scan(scanner.get(), chunk.data(), static_cast<size_t>(bytes_read));
      if (r != YRX_SUCCESS) {
        const char *err = yrx_last_error();
        const std::string emsg = err ? err : "yrx_scanner_scan failed";
        throw Errors::FailedToLoadCompiledRulesException("Scan failed: " + emsg);
      }
    }
  }

  return collector.matches;
}

// IScanningEngine interface implementations
SearchResult YScanningEngine::scanMemory(const std::vector<uint8_t> &data) {
  auto matches = _scanMemoryInternal(data);
  if (matches.empty()) {
    return std::nullopt;
  }

  std::string result;
  for (size_t i = 0; i < matches.size(); ++i) {
    result += matches[i];
    if (i < matches.size() - 1) {
      result += ", ";
    }
  }
  return result;
}

SearchResult YScanningEngine::scanFile(const std::string &filePath) {
  auto matches = _scanFileInternal(filePath);
  if (matches.empty()) {
    return std::nullopt;
  }

  std::string result;
  for (size_t i = 0; i < matches.size(); ++i) {
    result += matches[i];
    if (i < matches.size() - 1) {
      result += ", ";
    }
  }
  return result;
}

// Extended methods with scoring
YaraScanResult YScanningEngine::scanMemoryWithScoring(const std::vector<uint8_t> &data) {
  YaraScanResult result;
  result.matchedRules = _scanMemoryInternal(data);
  result.scoring = m_scoringSystem.analyze(result.matchedRules);
  return result;
}

YaraScanResult YScanningEngine::scanFileWithScoring(const std::string &filePath) {
  YaraScanResult result;
  result.matchedRules = _scanFileInternal(filePath);
  result.scoring = m_scoringSystem.analyze(result.matchedRules);
  return result;
}
