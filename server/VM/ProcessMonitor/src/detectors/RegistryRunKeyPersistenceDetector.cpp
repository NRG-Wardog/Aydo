#include "RegistryRunKeyPersistenceDetector.hpp"

#include <algorithm>

#include "ThreadHelpers.hpp"

std::vector<Finding> RegistryRunKeyPersistenceDetector::evaluate(const NormalizedEvent &ne,
                                                                 ThreadCaches &) {
  if (!isMatch(ne)) {
    return {};
  }

  const auto now = ThreadHelpers::eventTsOrNow(ne);
  const DWORD srcPid = static_cast<DWORD>(ThreadHelpers::actorPidOrFallback(ne));
  const DWORD tgtPid = ThreadHelpers::getTargetPid(ne).value_or(srcPid);
  const DWORD tid = ne.tid;

  if (srcPid == 0) {
    return {};
  }
  if (_isDuplicate(srcPid, tgtPid, tid, now)) {
    return {};
  }

  return {_buildFinding(ne, srcPid, tgtPid, tid)};
}

bool RegistryRunKeyPersistenceDetector::isMatch(const NormalizedEvent &ne) const {
  return ThreadHelpers::looksLikeRegistryRunKeyPersistence(ne);
}

bool RegistryRunKeyPersistenceDetector::_isDuplicate(
    DWORD srcPid,
    DWORD tgtPid,
    DWORD tid,
    std::chrono::time_point<std::chrono::system_clock> now) {
  const auto key = std::make_tuple(srcPid, tgtPid, tid);
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

Finding RegistryRunKeyPersistenceDetector::_buildFinding(const NormalizedEvent &ne,
                                                         DWORD srcPid,
                                                         DWORD tgtPid,
                                                         DWORD tid) const {
  nlohmann::json ev;
  ev["provider"] = ne.provider;
  ev["eventId"] = ne.eventId;
  ev["srcPid"] = srcPid;
  ev["tgtPid"] = tgtPid;
  ev["tid"] = tid;
  if (auto s = ThreadHelpers::getObjectName(ne)) {
    ev["object"] = *s;
  }
  if (auto s = ThreadHelpers::getStr(ne, "event")) {
    ev["event"] = *s;
  }

  Finding finding;
  finding.type = "RegistryRunKeyPersistence";
  finding.severity = SEVERITY;
  finding.confidence = CONFIDENCE;
  finding.ts = ne.ts;
  finding.source_pid = srcPid;
  finding.target_pid = tgtPid;
  finding.tid = tid;
  finding.evidence_json = ev.dump();
  return finding;
}


