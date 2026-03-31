#pragma once

#include <cstddef>
#include <cstdint>

namespace Constants {
inline constexpr int DEFAULT_TRACE_DURATION_SECONDS = 60;
inline constexpr int BITNESS_32 = 32;
inline constexpr int BITNESS_64 = 64;
inline constexpr int GUID_STRING_BUFFER_CHARS = 64;
inline constexpr int JSON_INDENT_WIDTH = 2;
inline constexpr int IP_PROTOCOL_TCP = 6;
inline constexpr int IP_PROTOCOL_UDP = 17;
inline constexpr int HOST_NAME_BUFFER_CHARS = 256;
inline constexpr int SQLITE_BUSY_TIMEOUT_MS = 5000;
inline constexpr int MILLISECONDS_PER_SECOND = 1000;
inline constexpr std::uint32_t INVALID_PID = 0xFFFFFFFFu;
inline constexpr std::size_t SNAKE_CASE_EXTRA_CAPACITY = 8;
} // namespace Constants


