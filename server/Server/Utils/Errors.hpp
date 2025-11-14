#pragma once
#include <stdexcept>
#include <string>

namespace Utils::Errors {

class DatabaseEnumParseError : public std::runtime_error {
public:
  explicit DatabaseEnumParseError(const std::string &enumName, const std::string &value)
      : std::runtime_error("Can't parse enum value '" + value + "' for enum type " + enumName)
      , m_enumName(enumName)
      , m_value(value) {}

  [[nodiscard]] const std::string &getEnumName() const { return m_enumName; }
  [[nodiscard]] const std::string &getValue() const { return m_value; }

private:
  std::string m_enumName;
  std::string m_value;
};

} // namespace Utils::Errors
