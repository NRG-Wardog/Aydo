#include "RemoteThreadCreationDetector.hpp"

#include <algorithm>

#include "ThreadHelpers.hpp"

std::vector<Finding> RemoteThreadCreationDetector::evaluate(const NormalizedEvent &ne, ThreadCaches &caches) {
  const auto now = ThreadHelpers::eventTsOrNow(ne);
  std::vector<Finding> findings;

  const auto srcPid = static_cast<DWORD>(ThreadHelpers::actorPidOrFallback(ne));

  // Path 1: explicit remote-thread API match plus recent access correlation.
  if (isMatch(ne)) {
    DWORD tgtPid = 0;
    DWORD tgtTid = 0;
    if (_tryGetTarget(ne, tgtPid, tgtTid) &&
        srcPid != 0 &&
        tgtPid != 0 &&
        srcPid != tgtPid &&
        caches.hasRecentProcessAccess(srcPid, tgtPid, now, CORRELATION_WINDOW) &&
        !_isDuplicate(srcPid, tgtPid, tgtTid, now)) {
      findings.emplace_back(_buildFinding(ne, srcPid, tgtPid, tgtTid, DEFAULT_SEVERITY + 1, DEFAULT_CONFIDENCE));
    }
  }

  // Path 2: fallback heuristic, thread start in target after cross-proc access.
  if (ThreadHelpers::isThreadStart(ne)) {
    const auto targetPid = ThreadHelpers::getTargetPid(ne);
    const auto targetTid = ThreadHelpers::getTargetTid(ne);
    if (targetPid && *targetPid != 0) {
      if (auto recentSource = caches.findRecentSourceForTarget(static_cast<DWORD>(*targetPid), now, CORRELATION_WINDOW);
          recentSource && *recentSource != *targetPid) {
        const DWORD tgtTid = targetTid ? static_cast<DWORD>(*targetTid) : 0;
        if (!_isDuplicate(*recentSource, static_cast<DWORD>(*targetPid), tgtTid, now)) {
          findings.emplace_back(_buildFinding(ne, *recentSource, static_cast<DWORD>(*targetPid), tgtTid, DEFAULT_CONFIDENCE, FALLBACK_CONFIDENCE));
        }
      }
    }
  }

  return findings;
}

bool RemoteThreadCreationDetector::_isDuplicate(
    DWORD srcPid,
    DWORD tgtPid,
    DWORD tgtTid,
    std::chrono::time_point<std::chrono::system_clock> now) {
  const auto key = std::make_tuple(srcPid, tgtPid, tgtTid);
  if (const auto it = m_recentFindings.find(key); it != m_recentFindings.end() && (now - it->second) <= DEDUP_WINDOW) {
    return true;
  }

  m_recentFindings[key] = now;
  std::erase_if(m_recentFindings, [&now](const auto &kv) {
    return (now - kv.second) > IThreadDetector::DEDUP_RETENTION_WINDOW;
  });
  return false;
}

bool RemoteThreadCreationDetector::isMatch(const NormalizedEvent &ne) const {
  return ThreadHelpers::isRemoteThread(ne);
}

bool RemoteThreadCreationDetector::_tryGetTarget(const NormalizedEvent &ne, DWORD &targetPid, DWORD &targetTid) const {
  if (auto p = ThreadHelpers::getTargetPid(ne)) {
    targetPid = static_cast<DWORD>(*p);
  } else {
    return false;
  }

  if (auto t = ThreadHelpers::getTargetTid(ne)) {
    targetTid = static_cast<DWORD>(*t);
  } else {
    targetTid = 0;
  }

  return (targetPid != 0);
}

Finding RemoteThreadCreationDetector::_buildFinding(const NormalizedEvent &ne,
                                                    DWORD srcPid,
                                                    DWORD tgtPid,
                                                    DWORD tgtTid,
                                                    int severity,
                                                    int confidence) const {
  nlohmann::json ev;
  ev["provider"] = ne.provider;
  ev["eventId"] = ne.eventId;
  if (auto s = ThreadHelpers::getStr(ne, "event")) {
    ev["event"] = *s;
  }
  if (auto s = ThreadHelpers::getStr(ne, "task_name")) {
    ev["task_name"] = *s;
  }
  ev["srcPid"] = srcPid;
  ev["tgtPid"] = tgtPid;
  ev["tgtTid"] = tgtTid;

  Finding f;
  f.type = "RemoteThreadCreation";
  f.severity = severity;
  f.confidence = confidence;
  f.ts = ne.ts;
  f.source_pid = srcPid;
  f.target_pid = tgtPid;
  f.tid = tgtTid;
  f.evidence_json = ev.dump();
  return f;
}

