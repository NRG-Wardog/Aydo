#pragma once

#include <chrono>
#include <map>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "IThreadDetector.hpp"

class LsassCredentialAccessDetector : public IThreadDetector {
public:
  std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) override;
  std::string name() const override {
    return "LsassCredentialAccessDetector";
  }
  bool isMatch(const NormalizedEvent &ne, ThreadCaches &caches) const;

private:
  static constexpr auto DEDUP_WINDOW = std::chrono::seconds(15);
  static constexpr int SEVERITY = 9;
  static constexpr int CONFIDENCE = 80;

  bool _isDuplicate(DWORD srcPid,
                    DWORD tgtPid,
                    DWORD tid,
                    std::chrono::time_point<std::chrono::system_clock> now);
  Finding _buildFinding(const NormalizedEvent &ne,
                        DWORD srcPid,
                        DWORD tgtPid,
                        DWORD tid,
                        uint64_t desiredAccess,
                        std::string_view targetImage) const;

  std::map<std::tuple<DWORD, DWORD, DWORD>, std::chrono::time_point<std::chrono::system_clock>> m_recentFindings;
};

