#pragma once
#include "pch.h"
#include <variant>

using FieldValue = std::variant<
    uint64_t,
    int64_t,
    uint32_t,
    int32_t,
    bool,
    std::wstring,
    std::string>;


struct NormalizedEvent {
  std::chrono::time_point<std::chrono::system_clock> ts;
  DWORD pid;
  DWORD tid;
  std::string provider;
  int eventId;
  std::map<std::string, FieldValue> fields;
};