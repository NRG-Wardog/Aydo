#pragma once

#include <cstdint>
#include <string_view>

namespace AttackMetadataConstants {
inline constexpr std::uint64_t ACCESS_VM_READ = 0x0010ULL;
inline constexpr std::uint64_t ACCESS_VM_WRITE = 0x0020ULL;
inline constexpr std::uint64_t ACCESS_VM_OPERATION = 0x0008ULL;
inline constexpr std::uint64_t ACCESS_DUP_HANDLE = 0x0040ULL;
inline constexpr std::uint64_t ACCESS_QUERY_INFORMATION = 0x0400ULL;
inline constexpr std::uint64_t ACCESS_QUERY_LIMITED_INFORMATION = 0x1000ULL;
inline constexpr std::string_view INJECTION_PREVENTION =
    "Use code integrity, EDR memory protections, and block unauthorized cross-process handle access.";
} // namespace AttackMetadataConstants
