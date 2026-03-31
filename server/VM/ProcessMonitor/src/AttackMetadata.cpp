#include "AttackMetadata.hpp"

#include <cctype>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>

#include "AttackMetadataConstants.hpp"
#include "Finding.hpp"

std::string s_toLower(std::string_view value) {
  std::string lower;
  lower.reserve(value.size());
  for (const char ch : value) {
    lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return lower;
}

bool s_containsI(std::string_view haystack, std::string_view needle) {
  if (needle.empty()) {
    return true;
  }

  const std::string hay = s_toLower(haystack);
  const std::string ndl = s_toLower(needle);
  return hay.find(ndl) != std::string::npos;
}

std::string s_getString(const nlohmann::json &object, const char *key) {
  if (!object.is_object()) {
    return {};
  }
  auto it = object.find(key);
  if (it == object.end() || !it->is_string()) {
    return {};
  }
  return it->get<std::string>();
}

std::string s_getFirstString(const nlohmann::json &object,
                             std::initializer_list<const char *> keys) {
  for (const char *key : keys) {
    const std::string value = s_getString(object, key);
    if (!value.empty()) {
      return value;
    }
  }
  return {};
}

std::optional<uint64_t> s_parseUnsigned(const nlohmann::json &value) {
  try {
    if (value.is_number_unsigned()) {
      return value.get<uint64_t>();
    }
    if (value.is_number_integer()) {
      const auto parsed = value.get<int64_t>();
      if (parsed >= 0) {
        return static_cast<uint64_t>(parsed);
      }
      return std::nullopt;
    }
    if (value.is_string()) {
      const std::string text = value.get<std::string>();
      if (text.empty()) {
        return std::nullopt;
      }
      return std::stoull(text, nullptr, 0);
    }
  } catch (...) {
  }
  return std::nullopt;
}

std::optional<uint64_t> s_getFirstUnsigned(const nlohmann::json &object,
                                           std::initializer_list<const char *> keys) {
  if (!object.is_object()) {
    return std::nullopt;
  }
  for (const char *key : keys) {
    auto it = object.find(key);
    if (it == object.end() || it->is_null()) {
      continue;
    }
    if (auto parsed = s_parseUnsigned(*it)) {
      return parsed;
    }
  }
  return std::nullopt;
}

bool s_hasAnyToken(std::string_view text,
                   std::initializer_list<std::string_view> tokens) {
  for (const auto token : tokens) {
    if (s_containsI(text, token)) {
      return true;
    }
  }
  return false;
}

AttackMetadata s_makeMetadata(std::string_view tactic,
                              std::string_view technique,
                              std::string_view subTechnique,
                              std::string_view reference,
                              std::string_view prevention) {
  AttackMetadata metadata;
  metadata.tactic = std::string(tactic);
  metadata.technique = std::string(technique);
  metadata.sub_technique = std::string(subTechnique);
  metadata.reference = std::string(reference);
  metadata.prevention = std::string(prevention);
  return metadata;
}

AttackMetadata s_injectionMetadata(std::string_view subTechnique = {}) {
  if (subTechnique.empty()) {
    return s_makeMetadata(
        "Defense Evasion",
        "T1055",
        "",
        "https://attack.mitre.org/techniques/T1055/",
        AttackMetadataConstants::INJECTION_PREVENTION);
  }

  if (subTechnique == "T1055.004") {
    return s_makeMetadata(
        "Defense Evasion",
        "T1055",
        "T1055.004",
        "https://attack.mitre.org/techniques/T1055/004/",
        AttackMetadataConstants::INJECTION_PREVENTION);
  }

  if (subTechnique == "T1055.003") {
    return s_makeMetadata(
        "Defense Evasion",
        "T1055",
        "T1055.003",
        "https://attack.mitre.org/techniques/T1055/003/",
        AttackMetadataConstants::INJECTION_PREVENTION);
  }

  return s_injectionMetadata();
}

namespace AttackMetadataCatalog {

AttackMetadata forFindingType(std::string_view findingType) {
  if (findingType == "RemoteThreadCreation") {
    return s_injectionMetadata();
  }
  if (findingType == "AsynchronousProcedureCallQueueing") {
    return s_injectionMetadata("T1055.004");
  }
  if (findingType == "ThreadHijackHeuristic") {
    return s_injectionMetadata("T1055.003");
  }
  if (findingType == "ThreatIntelInjection") {
    return s_injectionMetadata();
  }
  if (findingType == "RegistryRunKeyPersistence") {
    return s_makeMetadata(
        "Persistence",
        "T1547.001",
        "T1547.001",
        "https://attack.mitre.org/techniques/T1547/001/",
        "Restrict write access to autorun registry keys and alert on non-admin modifications.");
  }
  if (findingType == "ScheduledTaskPersistence") {
    return s_makeMetadata(
        "Persistence",
        "T1053.005",
        "T1053.005",
        "https://attack.mitre.org/techniques/T1053/005/",
        "Constrain task creation rights and monitor task registration updates from untrusted processes.");
  }
  if (findingType == "ServicePersistence") {
    return s_makeMetadata(
        "Persistence",
        "T1543.003",
        "T1543.003",
        "https://attack.mitre.org/techniques/T1543/003/",
        "Limit service control permissions and monitor service creation/configuration changes.");
  }
  if (findingType == "LsassCredentialAccess") {
    return s_makeMetadata(
        "Credential Access",
        "T1003.001",
        "T1003.001",
        "https://attack.mitre.org/techniques/T1003/001/",
        "Enable LSASS protection and alert on suspicious process handle access to lsass.exe.");
  }
  return {};
}

AttackMetadata forEventJson(const nlohmann::json &eventJson) {
  if (!eventJson.is_object()) {
    return {};
  }

  const std::string provider = s_toLower(s_getString(eventJson, "provider"));
  const std::string eventName = s_toLower(s_getString(eventJson, "event"));
  const std::string taskName = s_toLower(s_getString(eventJson, "task_name"));

  const nlohmann::json *props = nullptr;
  if (auto it = eventJson.find("props"); it != eventJson.end() && it->is_object()) {
    props = std::addressof(*it);
  }

  std::string objectName;
  std::string targetImage;
  std::optional<uint64_t> desiredAccess;
  if (props != nullptr) {
    objectName = s_toLower(s_getFirstString(
        *props,
        {"ObjectName", "TargetObject", "RegName", "KeyName", "Path"}));
    targetImage = s_toLower(s_getFirstString(
        *props,
        {"TargetImage", "TargetProcessName", "Image", "ImagePath"}));
    desiredAccess = s_getFirstUnsigned(
        *props,
        {"DesiredAccess", "GrantedAccess"});
  }

  if (targetImage.empty()) {
    targetImage = s_toLower(s_getString(eventJson, "TargetImage"));
  }
  if (!desiredAccess.has_value()) {
    desiredAccess = s_getFirstUnsigned(eventJson, {"DesiredAccess", "GrantedAccess"});
  }

  if (s_containsI(targetImage, "lsass.exe")) {
    const uint64_t access = desiredAccess.value_or(0);
    const uint64_t suspiciousMask = AttackMetadataConstants::ACCESS_VM_READ |
                                    AttackMetadataConstants::ACCESS_VM_WRITE |
                                    AttackMetadataConstants::ACCESS_VM_OPERATION |
                                    AttackMetadataConstants::ACCESS_DUP_HANDLE |
                                    AttackMetadataConstants::ACCESS_QUERY_INFORMATION |
                                    AttackMetadataConstants::ACCESS_QUERY_LIMITED_INFORMATION;
    if (access == 0 || (access & suspiciousMask) != 0) {
      return forFindingType("LsassCredentialAccess");
    }
  }

  if (s_containsI(objectName, "\\software\\microsoft\\windows\\currentversion\\run") ||
      s_containsI(objectName, "\\software\\microsoft\\windows\\currentversion\\runonce") ||
      s_containsI(objectName, "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run")) {
    return forFindingType("RegistryRunKeyPersistence");
  }

  if (s_containsI(provider, "taskscheduler") ||
      s_containsI(provider, "task scheduler") ||
      s_containsI(eventName, "registertask") ||
      s_containsI(eventName, "task created") ||
      s_containsI(objectName, "\\windows\\system32\\tasks\\")) {
    return forFindingType("ScheduledTaskPersistence");
  }

  if (s_containsI(provider, "services") ||
      s_containsI(eventName, "createservice") ||
      s_containsI(eventName, "changeserviceconfig") ||
      s_containsI(objectName, "\\system\\currentcontrolset\\services\\")) {
    return forFindingType("ServicePersistence");
  }

  const bool hasInjectionToken =
      s_hasAnyToken(eventName, {"createremotethread", "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc", "ntqueueapcthread", "setthreadcontext", "suspendthread", "resumethread"}) ||
      s_hasAnyToken(taskName, {"thread", "apc", "injection"});
  if (hasInjectionToken ||
      s_containsI(provider, "threat-intelligence") ||
      s_containsI(provider, "kernel-audit-api-calls")) {
    if (s_hasAnyToken(eventName, {"queueuserapc", "ntqueueapcthread", "apc"})) {
      return s_injectionMetadata("T1055.004");
    }
    if (s_hasAnyToken(eventName, {"setthreadcontext", "suspendthread", "resumethread", "hijack"})) {
      return s_injectionMetadata("T1055.003");
    }
    return s_injectionMetadata();
  }

  return {};
}

void applyToJson(const AttackMetadata &metadata, nlohmann::json &eventJson) {
  if (metadata.empty()) {
    return;
  }
  eventJson["AttackTactic"] = metadata.tactic;
  eventJson["AttackTechnique"] = metadata.technique;
  eventJson["AttackSubTechnique"] = metadata.sub_technique;
  eventJson["AttackReference"] = metadata.reference;
  eventJson["Prevention"] = metadata.prevention;
}

void applyToFinding(Finding &finding) {
  if (finding.hasAttackMetadata()) {
    return;
  }
  const AttackMetadata metadata = forFindingType(finding.type);
  if (metadata.empty()) {
    return;
  }
  finding.attack_tactic = metadata.tactic;
  finding.attack_technique = metadata.technique;
  finding.attack_sub_technique = metadata.sub_technique;
  finding.attack_reference = metadata.reference;
  finding.prevention = metadata.prevention;
}

} // namespace AttackMetadataCatalog
