#include "ThreatIntelInjectionDetector.hpp"

#include <algorithm>

#include "ThreadHelpers.hpp"

std::vector<Finding> ThreatIntelInjectionDetector::evaluate(const NormalizedEvent &ne,
                                                            ThreadCaches &caches) {
  if (!isMatch(ne)) {
    return {};
  }

  const auto now = ThreadHelpers::eventTsOrNow(ne);
  const DWORD srcPid = static_cast<DWORD>(ThreadHelpers::actorPidOrFallback(ne));

  DWORD tgtPid = 0;
  DWORD tgtTid = 0;
  if (!_tryGetTarget(ne, tgtPid, tgtTid)) {
    return {};
  }

  if (srcPid == 0 || tgtPid == 0 || srcPid == tgtPid) {
    return {};
  }

  if (!ThreadHelpers::isThreatIntelProvider(ne) &&
      !caches.hasRecentProcessAccess(srcPid, tgtPid, now, CORRELATION_WINDOW)) {
    return {};
  }

  if (_isDuplicate(srcPid, tgtPid, tgtTid, now)) {
    return {};
  }

  return {_buildFinding(ne, srcPid, tgtPid, tgtTid)};
}

bool ThreatIntelInjectionDetector::isMatch(const NormalizedEvent &ne) const {
  if (ThreadHelpers::isThreatIntelProvider(ne)) {
    return true;
  }

  const auto eventName = ThreadHelpers::bestName(ne);
  return ThreadHelpers::containsI(eventName, "injection") ||
         ThreadHelpers::containsI(eventName, "createremotethread");
}

bool ThreatIntelInjectionDetector::_isDuplicate(
    DWORD srcPid,
    DWORD tgtPid,
    DWORD tgtTid,
    std::chrono::time_point<std::chrono::system_clock> now) {
  const auto key = std::make_tuple(srcPid, tgtPid, tgtTid);
  if (const auto it = m_recentFindings.find(key);
      it != m_recentFindings.end() && (now - it->second) <= DEDUP_WINDOW) {
    return true;
  }

  m_recentFindings[key] = now;
  std::erase_if(m_recentFindings, [&now](const auto &kv) {
    return (now - kv.second) > IThreadDetector::DEDUP_RETENTION_WINDOW;
  });
  return false;
}

bool ThreatIntelInjectionDetector::_tryGetTarget(const NormalizedEvent &ne,
                                                 DWORD &targetPid,
                                                 DWORD &targetTid) const {
  if (auto pid = ThreadHelpers::getTargetPid(ne)) {
    targetPid = static_cast<DWORD>(*pid);
  } else {
    return false;
  }

  if (auto tid = ThreadHelpers::getTargetTid(ne)) {
    targetTid = static_cast<DWORD>(*tid);
  } else {
    targetTid = 0;
  }

  return targetPid != 0;
}

Finding ThreatIntelInjectionDetector::_buildFinding(const NormalizedEvent &ne,
                                                    DWORD srcPid,
                                                    DWORD tgtPid,
                                                    DWORD tgtTid) const {
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

  Finding finding;
  finding.type = "ThreatIntelInjection";
  finding.severity = SEVERITY;
  finding.confidence = CONFIDENCE;
  finding.ts = ne.ts;
  finding.source_pid = srcPid;
  finding.target_pid = tgtPid;
  finding.tid = tgtTid;
  finding.evidence_json = ev.dump();
  return finding;
}

