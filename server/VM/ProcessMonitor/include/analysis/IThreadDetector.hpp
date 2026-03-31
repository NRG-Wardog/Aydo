#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "Finding.hpp"
#include "NormalizedEvent.hpp"
#include "ThreadCaches.hpp"

class IThreadDetector {
public:
  static constexpr int DEFAULT_SEVERITY = 7;
  static constexpr int DEFAULT_CONFIDENCE = 60;
  static constexpr auto DEDUP_RETENTION_WINDOW = std::chrono::minutes(1);

  virtual ~IThreadDetector() = default;

  virtual std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) = 0;
  virtual std::string name() const = 0;
};

