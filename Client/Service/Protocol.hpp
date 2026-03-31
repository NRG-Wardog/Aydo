#pragma once

#include <chrono>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <variant>

namespace Protocol {

inline std::string getTimestamp() {
  auto now = std::chrono::system_clock::now();
  auto in_time_t = std::chrono::system_clock::to_time_t(now);
  struct tm buf;
  if (gmtime_s(&buf, &in_time_t) != 0) {
    return "unknown-time";
  }
  std::stringstream ss;
  ss << std::put_time(&buf, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

// --- Outgoing Events (Service -> GUI) ---

enum class EventType {
  Status,
  Info,
  ScanProgress,
  ScanComplete,
  ThreatDetected,
  CapabilitiesUpdate,
  Quarantine,
  Delete,
  Heartbeat,
  Handshake
};

inline std::string eventTypeToString(EventType t) {
  switch (t) {
  case EventType::Status:
    return "status";
  case EventType::Info:
    return "info";
  case EventType::ScanProgress:
    return "scan_progress";
  case EventType::ScanComplete:
    return "scan_complete";
  case EventType::ThreatDetected:
    return "threat_detected";
  case EventType::CapabilitiesUpdate:
    return "capabilities_update";
  case EventType::Quarantine:
    return "quarantine";
  case EventType::Delete:
    return "delete";
  case EventType::Heartbeat:
    return "heartbeat";
  case EventType::Handshake:
    return "handshake";
  default:
    return "unknown";
  }
}

struct Event {
  EventType type;
  std::string severity; // "low", "medium", "high"
  std::string message;
  nlohmann::json data;
  std::string timestamp;

  Event(EventType t, std::string sev, std::string msg, nlohmann::json d = nlohmann::json::object())
      : type(t)
      , severity(std::move(sev))
      , message(std::move(msg))
      , data(std::move(d))
      , timestamp(getTimestamp()) {
  }
};

inline void to_json(nlohmann::json &j, const Event &e) {
  j = nlohmann::json{
      {"type", eventTypeToString(e.type)},
      {"severity", e.severity},
      {"message", e.message},
      {"data", e.data},
      {"timestamp", e.timestamp}};
}

// Helper to wrap message in newline for pipe communication
inline std::string serialize(const nlohmann::json &j) {
  return j.dump() + "\n";
}

} // namespace Protocol
