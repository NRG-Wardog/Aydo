#pragma once
#include <chrono>
#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "IThreadDetector.hpp"

class RemoteThreadCreationDetector : public IThreadDetector {
public:
  std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) override;
  std::string name() const override { return "RemoteThreadCreationDetector"; }
  bool isMatch(const NormalizedEvent &ne) const;

private:
  static constexpr auto CORRELATION_WINDOW = std::chrono::seconds(10);
  static constexpr auto DEDUP_WINDOW = std::chrono::seconds(5);
  static constexpr int FALLBACK_CONFIDENCE = 70;

  bool _isDuplicate(DWORD srcPid,
                    DWORD tgtPid,
                    DWORD tgtTid,
                    std::chrono::time_point<std::chrono::system_clock> now);
  bool _tryGetTarget(const NormalizedEvent &ne, DWORD &targetPid, DWORD &targetTid) const;
  Finding _buildFinding(const NormalizedEvent &ne, DWORD srcPid, DWORD tgtPid, DWORD tgtTid,
                        int severity, int confidence) const;
  std::map<std::tuple<DWORD, DWORD, DWORD>, std::chrono::time_point<std::chrono::system_clock>> m_recentFindings;
};

