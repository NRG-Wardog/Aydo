#pragma once
#include <chrono>
#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "IThreadDetector.hpp"

class ThreadHijackDetector : public IThreadDetector {
public:
  std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) override;
  std::string name() const override { return "ThreadHijackDetector"; }

private:
  static constexpr auto SEQUENCE_WINDOW = std::chrono::seconds(10);
  static constexpr auto DEDUP_WINDOW = std::chrono::seconds(5);

  bool _isDuplicate(DWORD actorPid,
                    DWORD ownerPid,
                    DWORD tid,
                    std::chrono::time_point<std::chrono::system_clock> now);
  Finding _buildFinding(const NormalizedEvent &ne, DWORD ownerPid, DWORD tid, int severity, int confidence, const char *phase) const;

  std::map<std::tuple<DWORD, DWORD, DWORD>, std::chrono::time_point<std::chrono::system_clock>> m_recentFindings;
};

