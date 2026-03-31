#include "ThreadAnalysisEngine.hpp"

ThreadAnalysisEngine::ThreadAnalysisEngine(ThreadCaches *c, EventWriter *w)
    : ownedDetectors{}
    , detectors{}
    , caches(c)
    , writer(w) {
  ownedDetectors.emplace_back(std::make_unique<RemoteThreadCreationDetector>());
  ownedDetectors.emplace_back(std::make_unique<AsynchronousProcedureCallQueueingDetector>());
  ownedDetectors.emplace_back(std::make_unique<ThreadHijackDetector>());
  ownedDetectors.emplace_back(std::make_unique<ThreatIntelInjectionDetector>());
  ownedDetectors.emplace_back(std::make_unique<RegistryRunKeyPersistenceDetector>());
  ownedDetectors.emplace_back(std::make_unique<ScheduledTaskPersistenceDetector>());
  ownedDetectors.emplace_back(std::make_unique<ServicePersistenceDetector>());
  ownedDetectors.emplace_back(std::make_unique<LsassCredentialAccessDetector>());

  detectors.reserve(ownedDetectors.size());
  for (auto &detector : ownedDetectors) {
    detectors.push_back(detector.get());
  }
}

void ThreadAnalysisEngine::onEvent(const NormalizedEvent &ne) {
  if (!caches || !writer) {
    return;
  }

  // update state for sequences/correlation
  caches->update(ne);

  // run detectors and emit findings
  for (auto &d : detectors) {
    auto findings = d->evaluate(ne, *caches);
    for (const auto &f : findings) {
      writer->writeFinding(f);
    }
  }

  // cleanup TTL based on event time (or system_clock::now())
  caches->cleanup(ne.ts);
}
