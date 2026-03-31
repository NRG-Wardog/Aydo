#include "ThreadCaches.hpp"
#include "ThreadHelpers.hpp"

#include <algorithm>
#include <chrono>
#include <optional>
#include <utility>

void ThreadCaches::update(const NormalizedEvent &e) {
  const auto now = ThreadHelpers::eventTsOrNow(e);
  const auto srcPid = ThreadHelpers::getSourcePid(e);
  const auto tgtPid = ThreadHelpers::getTargetPid(e);
  const auto tgtTid = ThreadHelpers::getTargetTid(e);

  if (auto image = ThreadHelpers::getStr(e, "Image"); image && !image->empty()) {
    rememberProcessImage(e.pid, *image, now);
    if (auto processPid = ThreadHelpers::getU32(e, "ProcessId")) {
      rememberProcessImage(static_cast<DWORD>(*processPid), *image, now);
    }
  }
  if (srcPid) {
    if (auto sourceImage = ThreadHelpers::getStr(e, "SourceImage"); sourceImage && !sourceImage->empty()) {
      rememberProcessImage(static_cast<DWORD>(*srcPid), *sourceImage, now);
    }
  }
  if (tgtPid) {
    if (auto targetImage = ThreadHelpers::getStr(e, "TargetImage"); targetImage && !targetImage->empty()) {
      rememberProcessImage(static_cast<DWORD>(*tgtPid), *targetImage, now);
    }
  }

  // Track owner mapping from kernel thread-start events.
  if (ThreadHelpers::isThreadStart(e) && tgtTid && *tgtTid != 0) {
    auto &st = byTid[*tgtTid];
    if (auto ownerPid = ThreadHelpers::getU32(e, "ProcessId")) {
      st.ownerPid = static_cast<DWORD>(*ownerPid);
    } else if (tgtPid) {
      st.ownerPid = static_cast<DWORD>(*tgtPid);
    }
    st.lastObserved = now;
  }

  // Track sequence state for suspend/context/resume.
  const DWORD seqTid = tgtTid ? static_cast<DWORD>(*tgtTid) : e.tid;
  if (seqTid != 0) {
    auto &st = byTid[seqTid];
    if (st.ownerPid == 0 && tgtPid) {
      st.ownerPid = static_cast<DWORD>(*tgtPid);
    }

    const DWORD actorPid = srcPid ? static_cast<DWORD>(*srcPid) : e.pid;

    if (ThreadHelpers::isSuspend(e)) {
      st.lastSuspend = now;
      st.suspendActorPid = actorPid;
    }
    if (ThreadHelpers::isContextChange(e)) {
      st.lastContextChange = now;
      st.contextActorPid = actorPid;
    }
    if (ThreadHelpers::isResume(e)) {
      st.lastResume = now;
      st.resumeActorPid = actorPid;
    }
    st.lastObserved = now;
  }

  // Track cross-process access/action windows.
  if (srcPid && tgtPid &&
      *srcPid != 0 && *tgtPid != 0 &&
      *srcPid != *tgtPid) {
    auto &w = crossProcWindows[{static_cast<DWORD>(*srcPid), static_cast<DWORD>(*tgtPid)}];
    if (ThreadHelpers::isProcessAccess(e)) {
      w.lastProcessAccess = now;
    }
    if (ThreadHelpers::isRemoteThread(e)) {
      w.lastRemoteThread = now;
    }
    if (ThreadHelpers::isApcQueue(e)) {
      w.lastApcQueue = now;
    }
  }
}

void ThreadCaches::rememberProcessImage(
    DWORD pid,
    const std::string &image,
    std::chrono::time_point<std::chrono::system_clock> now) {
  if (pid == 0 || image.empty()) {
    return;
  }
  m_processImageByPid[pid] = std::make_pair(image, now);
}

std::optional<std::string> ThreadCaches::findProcessImage(DWORD pid) const {
  if (pid == 0) {
    return std::nullopt;
  }
  auto it = m_processImageByPid.find(pid);
  if (it == m_processImageByPid.end()) {
    return std::nullopt;
  }
  return it->second.first;
}

bool ThreadCaches::hasRecentProcessAccess(
    DWORD sourcePid,
    DWORD targetPid,
    std::chrono::time_point<std::chrono::system_clock> now,
    std::chrono::seconds window) const {
  const auto it = crossProcWindows.find({sourcePid, targetPid});
  if (it == crossProcWindows.end()) {
    return false;
  }

  const auto ts = it->second.lastProcessAccess;
  if (ts.time_since_epoch().count() == 0) {
    return false;
  }

  return ts <= now && (now - ts) <= window;
}

std::optional<DWORD> ThreadCaches::findRecentSourceForTarget(
    DWORD targetPid,
    std::chrono::time_point<std::chrono::system_clock> now,
    std::chrono::seconds window) const {
  std::optional<DWORD> bestSource;
  std::chrono::time_point<std::chrono::system_clock> bestTs{};

  for (const auto &[key, val] : crossProcWindows) {
    const auto &[srcPid, tgtPid] = key;
    if (tgtPid != targetPid) {
      continue;
    }

    const auto ts = val.lastProcessAccess;
    if (ts.time_since_epoch().count() == 0) {
      continue;
    }
    if (ts > now || (now - ts) > window) {
      continue;
    }

    if (!bestSource || ts > bestTs) {
      bestSource = srcPid;
      bestTs = ts;
    }
  }

  return bestSource;
}

void ThreadCaches::cleanup(std::chrono::time_point<std::chrono::system_clock> now) {
  std::erase_if(byTid, [&](const auto &kv) {
    const auto &s = kv.second;
    const auto last = std::max({s.lastSuspend, s.lastResume, s.lastContextChange, s.lastObserved});
    if (last.time_since_epoch().count() == 0) {
      return true;
    }
    return (now - last) > TID_TTL;
  });

  std::erase_if(crossProcWindows, [&](const auto &kv) {
    const auto &w = kv.second;
    const auto last = std::max({w.lastProcessAccess, w.lastRemoteThread, w.lastApcQueue});
    if (last.time_since_epoch().count() == 0) {
      return true;
    }
    return (now - last) > XPROC_TTL;
  });

  std::erase_if(m_processImageByPid, [&](const auto &kv) {
    return (now - kv.second.second) > XPROC_TTL;
  });
}

