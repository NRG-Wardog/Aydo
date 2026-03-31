#pragma once
#include "pch.h"
#include <string>

struct Finding {
  std::string type;
  int severity;
  int confidence;
  std::chrono::time_point<std::chrono::system_clock> ts;
  DWORD source_pid;
  DWORD target_pid;
  DWORD tid;
  std::string evidence_json;
  std::string attack_tactic;
  std::string attack_technique;
  std::string attack_sub_technique;
  std::string attack_reference;
  std::string prevention;

  bool hasAttackMetadata() const {
    return !attack_technique.empty() || !attack_tactic.empty() || !attack_reference.empty();
  }
};
