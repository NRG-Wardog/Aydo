#pragma once

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>
#include "Finding.hpp"

struct AttackMetadata {
  std::string tactic;
  std::string technique;
  std::string sub_technique;
  std::string reference;
  std::string prevention;

  [[nodiscard]] bool empty() const {
    return tactic.empty() && technique.empty() && sub_technique.empty() &&
           reference.empty() && prevention.empty();
  }
};

namespace AttackMetadataCatalog {

AttackMetadata forFindingType(std::string_view findingType);
AttackMetadata forEventJson(const nlohmann::json &eventJson);

void applyToJson(const AttackMetadata &metadata, nlohmann::json &eventJson);
void applyToFinding(Finding &finding);

} // namespace AttackMetadataCatalog
