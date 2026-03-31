#include "LsassCredentialAccessDetector.hpp"

#include <algorithm>

#include "ThreadHelpers.hpp"

std::vector<Finding> LsassCredentialAccessDetector::evaluate(const NormalizedEvent &ne,
                                                             ThreadCaches &caches) {
  if (!isMatch(ne, caches)) {
    return {};
  }

  const auto now = ThreadHelpers::eventTsOrNow(ne);
  const DWORD srcPid = static_cast<DWORD>(ThreadHelpers::actorPidOrFallback(ne));
  const DWORD tgtPid = static_cast<DWORD>(ThreadHelpers::getTargetPid(ne).value_or(0));
  const DWORD tid = ThreadHelpers::getTargetTid(ne).value_or(ne.tid);

  const uint64_t accessMask = ThreadHelpers::getDesiredAccess(ne).value_or(0);

  std::string targetImage = ThreadHelpers::getTargetImage(ne).value_or({});
  if (targetImage.empty()) {
    if (auto resolved = caches.findProcessImage(tgtPid)) {
      targetImage = *resolved;
    }
  }

  if (srcPid == 0 || tgtPid == 0 || srcPid == tgtPid) {
    return {};
  }

  if (_isDuplicate(srcPid, tgtPid, tid, now)) {
    return {};
  }

  return {_buildFinding(ne, srcPid, tgtPid, tid, accessMask, targetImage)};
}

bool LsassCredentialAccessDetector::isMatch(const NormalizedEvent &ne,
                                            ThreadCaches &caches) const {
  if (!ThreadHelpers::isProcessAccess(ne)) {
    return false;
  }
  if (!ThreadHelpers::hasSuccessfulReturnCode(ne)) {
    return false;
  }

  const DWORD tgtPid = static_cast<DWORD>(ThreadHelpers::getTargetPid(ne).value_or(0));
  if (tgtPid == 0) {
    return false;
  }

  std::string targetImage = ThreadHelpers::getTargetImage(ne).value_or({});
  if (targetImage.empty()) {
    if (auto cached = caches.findProcessImage(tgtPid)) {
      targetImage = *cached;
    }
  }

  if (!ThreadHelpers::isLsassImage(targetImage)) {
    return false;
  }

  const uint64_t accessMask = ThreadHelpers::getDesiredAccess(ne).value_or(0);
  return ThreadHelpers::isSuspiciousProcessAccessMask(accessMask);
}

bool LsassCredentialAccessDetector::_isDuplicate(
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

Finding LsassCredentialAccessDetector::_buildFinding(const NormalizedEvent &ne,
                                                     DWORD srcPid,
                                                     DWORD tgtPid,
                                                     DWORD tid,
                                                     uint64_t desiredAccess,
                                                     std::string_view targetImage) const {
  nlohmann::json ev;
  ev["provider"] = ne.provider;
  ev["eventId"] = ne.eventId;
  if (auto s = ThreadHelpers::getStr(ne, "event")) {
    ev["event"] = *s;
  }
  ev["srcPid"] = srcPid;
  ev["tgtPid"] = tgtPid;
  ev["tid"] = tid;
  ev["targetImage"] = targetImage;
  ev["desiredAccess"] = desiredAccess;

  Finding finding;
  finding.type = "LsassCredentialAccess";
  finding.severity = SEVERITY;
  finding.confidence = CONFIDENCE;
  finding.ts = ne.ts;
  finding.source_pid = srcPid;
  finding.target_pid = tgtPid;
  finding.tid = tid;
  finding.evidence_json = ev.dump();
  return finding;
}


