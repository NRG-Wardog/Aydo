#pragma once

#include <krabs.hpp>

#include <optional>
#include <stdexcept>

class SafeKrabsParserSession {
public:
  explicit SafeKrabsParserSession(const krabs::schema &schema)
      : parser_(schema) {
  }

  template <typename T>
  std::optional<T> tryParse(const wchar_t *name) noexcept {
    if (poisoned_ || name == nullptr) {
      return std::nullopt;
    }

    try {
      return parser_.parse<T>(name);
    } catch (const std::out_of_range &) {
      // Out-of-range means payload traversal diverged from the schema;
      // parser state is unsafe to reuse for this record.
      poisoned_ = true;
      return std::nullopt;
    } catch (...) {
      return std::nullopt;
    }
  }

  bool isPoisoned() const noexcept {
    return poisoned_;
  }

private:
  krabs::parser parser_;
  bool poisoned_ = false;
};
