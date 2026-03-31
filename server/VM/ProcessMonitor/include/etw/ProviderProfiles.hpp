#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace ProviderProfiles {

inline constexpr std::size_t ANALYST_USER_PROVIDER_COUNT = 11;
inline constexpr std::array<const wchar_t *, ANALYST_USER_PROVIDER_COUNT> ANALYST_USER_PROVIDERS = {
    L"Microsoft-Windows-Kernel-Audit-API-Calls",
    L"Microsoft-Windows-Threat-Intelligence",
    L"Microsoft-Windows-TaskScheduler",
    L"Microsoft-Windows-Services",
    L"Microsoft-Windows-WMI-Activity",
    L"Microsoft-Windows-PowerShell",
    L"Microsoft-Windows-Bits-Client",
    L"Microsoft-Windows-CodeIntegrity",
    L"Microsoft-Windows-Windows Defender",
    L"Microsoft-Windows-DNS-Client",
    L"Microsoft-Windows-WinHTTP",
};

const std::array<const wchar_t *, ANALYST_USER_PROVIDER_COUNT> &getAnalystUserProviders();

bool isForbiddenProvider(std::wstring_view providerName);

} // namespace ProviderProfiles

