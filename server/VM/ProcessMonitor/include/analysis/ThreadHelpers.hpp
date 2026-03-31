#pragma once
#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

#include "NormalizedEvent.hpp"

namespace ThreadHelpers {
uint64_t packPids(uint32_t src, uint32_t tgt);
std::optional<uint32_t> getU32(const NormalizedEvent &e, std::string_view key);
std::optional<uint64_t> getU64(const NormalizedEvent &e, std::string_view key);
std::optional<uint32_t> getFirstU32(
    const NormalizedEvent &e,
    std::initializer_list<std::string_view> keys);
std::optional<std::string> getStr(const NormalizedEvent &e, std::string_view key);
std::optional<std::string> getFirstStr(const NormalizedEvent &e,
                                       std::initializer_list<std::string_view> keys);
bool containsI(std::string_view hay, std::string_view needle);
bool hasFieldNamedLike(const NormalizedEvent &e, std::string_view token);
std::string bestName(const NormalizedEvent &e);
std::optional<uint32_t> getSourcePid(const NormalizedEvent &e);
std::optional<uint32_t> getTargetPid(const NormalizedEvent &e);
std::optional<uint32_t> getTargetTid(const NormalizedEvent &e);
std::optional<uint64_t> getDesiredAccess(const NormalizedEvent &e);
std::optional<std::string> getObjectName(const NormalizedEvent &e);
std::optional<std::string> getImage(const NormalizedEvent &e);
std::optional<std::string> getTargetImage(const NormalizedEvent &e);
uint32_t actorPidOrFallback(const NormalizedEvent &e);
bool isKernelAuditApiProvider(const NormalizedEvent &e);
bool isThreatIntelProvider(const NormalizedEvent &e);
bool hasSuccessfulReturnCode(const NormalizedEvent &e);
bool isThreadStart(const NormalizedEvent &e);
bool isSuspend(const NormalizedEvent &e);
bool isResume(const NormalizedEvent &e);
bool isContextChange(const NormalizedEvent &e);
bool isProcessAccess(const NormalizedEvent &e);
bool isRemoteThread(const NormalizedEvent &e);
bool isApcQueue(const NormalizedEvent &e);
bool looksLikeRegistryRunKeyPersistence(const NormalizedEvent &e);
bool looksLikeScheduledTaskPersistence(const NormalizedEvent &e);
bool looksLikeServicePersistence(const NormalizedEvent &e);
bool isLsassImage(std::string_view image);
bool isSuspiciousProcessAccessMask(uint64_t accessMask);
std::chrono::time_point<std::chrono::system_clock> eventTsOrNow(const NormalizedEvent &e);

} // namespace ThreadHelpers
