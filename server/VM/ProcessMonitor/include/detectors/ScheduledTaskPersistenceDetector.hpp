#pragma once

#include <chrono>
#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "IThreadDetector.hpp"

class ScheduledTaskPersistenceDetector : public IThreadDetector {
public:
  std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) override;
  std::string name() const override {
    return "ScheduledTaskPersistenceDetector";
  }
  bool isMatch(const NormalizedEvent &ne) const;

private:
  static constexpr auto DEDUP_WINDOW = std::chrono::seconds(10);
  static constexpr int SEVERITY = 8;
  static constexpr int CONFIDENCE = 70;

  bool _isDuplicate(DWORD srcPid,
                    DWORD tgtPid,
                    DWORD tid,
                    std::chrono::time_point<std::chrono::system_clock> now);
  Finding _buildFinding(const NormalizedEvent &ne,
                        DWORD srcPid,
                        DWORD tgtPid,
                        DWORD tid) const;

  std::map<std::tuple<DWORD, DWORD, DWORD>, std::chrono::time_point<std::chrono::system_clock>> m_recentFindings;
};


