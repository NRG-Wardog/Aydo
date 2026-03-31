#include "ThreadHijackDetector.hpp"

#include <algorithm>

#include "ThreadHelpers.hpp"

std::vector<Finding> ThreadHijackDetector::evaluate(const NormalizedEvent &ne, ThreadCaches &caches) {
  if (!ThreadHelpers::isResume(ne)) {
    return {};
  }

  const auto targetTidOpt = ThreadHelpers::getTargetTid(ne);
  const auto targetTid = targetTidOpt ? static_cast<DWORD>(*targetTidOpt) : ne.tid;
  if (targetTid == 0) {
    return {};
  }

  const auto it = caches.byTid.find(targetTid);
  if (it == caches.byTid.end()) {
    return {};
  }

  const ThreadState &st = it->second;
  const auto now = ThreadHelpers::eventTsOrNow(ne);
  const DWORD actorPid = ThreadHelpers::actorPidOrFallback(ne);

  if (st.ownerPid == 0 || actorPid == 0 || actorPid == st.ownerPid) {
    return {};
  }

  if (st.lastSuspend.time_since_epoch().count() == 0 ||
      st.lastContextChange.time_since_epoch().count() == 0) {
    return {};
  }

  if (!(st.lastSuspend <= st.lastContextChange && st.lastContextChange <= now)) {
    return {};
  }

  if ((now - st.lastSuspend) > SEQUENCE_WINDOW) {
    return {};
  }

  if (st.suspendActorPid == 0 || st.contextActorPid == 0) {
    return {};
  }

  if (!(st.suspendActorPid == st.contextActorPid &&
        st.contextActorPid == actorPid)) {
    return {};
  }

  if (_isDuplicate(actorPid, st.ownerPid, targetTid, now)) {
    return {};
  }

  return {_buildFinding(ne, st.ownerPid, targetTid, DEFAULT_SEVERITY + 1, DEFAULT_CONFIDENCE, "resume_after_context_change")};
}

bool ThreadHijackDetector::_isDuplicate(
    DWORD actorPid,
    DWORD ownerPid,
    DWORD tid,
    std::chrono::time_point<std::chrono::system_clock> now) {
  const auto key = std::make_tuple(actorPid, ownerPid, tid);

  if (const auto it = m_recentFindings.find(key); it != m_recentFindings.end() && (now - it->second) <= DEDUP_WINDOW) {
    return true;
  }

  m_recentFindings[key] = now;
  std::erase_if(m_recentFindings, [&](const auto &kv) {
    return (now - kv.second) > IThreadDetector::DEDUP_RETENTION_WINDOW;
  });
  return false;
}

Finding ThreadHijackDetector::_buildFinding(const NormalizedEvent &ne,
                                            DWORD ownerPid,
                                            DWORD tid,
                                            int severity,
                                            int confidence,
                                            const char *phase) const {
  nlohmann::json ev;
  ev["provider"] = ne.provider;
  ev["eventId"] = ne.eventId;
  if (auto s = ThreadHelpers::getStr(ne, "event")) {
    ev["event"] = *s;
  }
  if (auto s = ThreadHelpers::getStr(ne, "task_name")) {
    ev["task_name"] = *s;
  }
  ev["ownerPid"] = ownerPid;
  ev["tid"] = tid;
  ev["phase"] = phase;

  Finding f;
  f.type = "ThreadHijackHeuristic";
  f.severity = severity;
  f.confidence = confidence;
  f.ts = ne.ts;
  f.source_pid = ThreadHelpers::actorPidOrFallback(ne);
  f.target_pid = ownerPid;
  f.tid = tid;
  f.evidence_json = ev.dump();
  return f;
}

