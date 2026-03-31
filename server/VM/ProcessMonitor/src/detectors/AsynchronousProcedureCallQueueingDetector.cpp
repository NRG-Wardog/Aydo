#include "AsynchronousProcedureCallQueueingDetector.hpp"

#include <algorithm>

#include "ThreadHelpers.hpp"

std::vector<Finding> AsynchronousProcedureCallQueueingDetector::evaluate(const NormalizedEvent &ne, ThreadCaches &caches) {
  if (!isMatch(ne)) {
    return {};
  }

  const auto now = ThreadHelpers::eventTsOrNow(ne);
  const auto srcPid = static_cast<DWORD>(ThreadHelpers::actorPidOrFallback(ne));

  DWORD tgtPid = 0;
  DWORD tgtTid = 0;
  if (!_tryGetTarget(ne, tgtPid, tgtTid)) {
    return {};
  }

  if (srcPid == 0 || tgtPid == 0 || srcPid == tgtPid) {
    return {};
  }

  if (!caches.hasRecentProcessAccess(srcPid, tgtPid, now, CORRELATION_WINDOW)) {
    return {};
  }

  if (_isDuplicate(srcPid, tgtPid, tgtTid, now)) {
    return {};
  }

  return {_buildFinding(ne, srcPid, tgtPid, tgtTid, DEFAULT_SEVERITY, DEFAULT_CONFIDENCE)};
}

bool AsynchronousProcedureCallQueueingDetector::_isDuplicate(
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

bool AsynchronousProcedureCallQueueingDetector::isMatch(const NormalizedEvent &ne) const {
  return ThreadHelpers::isApcQueue(ne);
}

bool AsynchronousProcedureCallQueueingDetector::_tryGetTarget(const NormalizedEvent &ne, DWORD &targetPid, DWORD &targetTid) const {
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

Finding AsynchronousProcedureCallQueueingDetector::_buildFinding(const NormalizedEvent &ne,
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
  f.type = "AsynchronousProcedureCallQueueing";
  f.severity = severity;
  f.confidence = confidence;
  f.ts = ne.ts;
  f.source_pid = srcPid;
  f.target_pid = tgtPid;
  f.tid = tgtTid;
  f.evidence_json = ev.dump();
  return f;
}

