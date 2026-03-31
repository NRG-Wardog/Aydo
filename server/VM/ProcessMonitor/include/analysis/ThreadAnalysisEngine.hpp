#pragma once
#include "EventWriter.hpp"
#include "IThreadDetector.hpp"
#include "ThreadCaches.hpp"
#include "AsynchronousProcedureCallQueueingDetector.hpp"
#include "LsassCredentialAccessDetector.hpp"
#include "RegistryRunKeyPersistenceDetector.hpp"
#include "RemoteThreadCreationDetector.hpp"
#include "ScheduledTaskPersistenceDetector.hpp"
#include "ServicePersistenceDetector.hpp"
#include "ThreatIntelInjectionDetector.hpp"
#include "ThreadHijackDetector.hpp"
#include <memory>


class ThreadAnalysisEngine {
public:
  ThreadAnalysisEngine(ThreadCaches *c, EventWriter *w);
  void onEvent(const NormalizedEvent& normEvent);

private:
  std::vector<std::unique_ptr<IThreadDetector>> ownedDetectors;
  std::vector<IThreadDetector *> detectors;
  ThreadCaches *caches;
  EventWriter *writer;
};
