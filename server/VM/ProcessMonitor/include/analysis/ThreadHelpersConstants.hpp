#pragma once

#include <cstdint>

namespace ThreadHelpersConstants {
inline constexpr int OPEN_PROCESS_EVENT_ID = 5;
inline constexpr int OPEN_THREAD_EVENT_ID = 6;
inline constexpr std::uint64_t ACCESS_VM_READ = 0x0010ULL;
inline constexpr std::uint64_t ACCESS_VM_WRITE = 0x0020ULL;
inline constexpr std::uint64_t ACCESS_VM_OPERATION = 0x0008ULL;
inline constexpr std::uint64_t ACCESS_DUP_HANDLE = 0x0040ULL;
inline constexpr std::uint64_t ACCESS_QUERY_INFO = 0x0400ULL;
inline constexpr std::uint64_t ACCESS_QUERY_LIMITED_INFO = 0x1000ULL;
} // namespace ThreadHelpersConstants
