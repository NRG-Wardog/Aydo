#pragma once

#include <ntifs.h>
#include <fltKernel.h>

enum ProcessAccessRights {
  PROCESS_TERMINATE = 0x0001,
  PROCESS_CREATE_THREAD = 0x0002,
  PROCESS_VM_OPERATION = 0x0008,
  PROCESS_VM_READ = 0x0010,
  PROCESS_VM_WRITE = 0x0020,
  PROCESS_DUPLICATE_HANDLE = 0x0040,
  PROCESS_SUSPEND_RESUME = 0x0800,
};

namespace ServiceProtection {
extern PVOID g_registrationHandle;
extern HANDLE g_servicePID;
extern PEPROCESS g_serviceProcess;
extern KSPIN_LOCK g_serviceLock;
extern BOOLEAN g_isInitialized;
extern LARGE_INTEGER g_RegCookie;
extern PFLT_FILTER g_filterHandle;

struct ProtectedServiceInfo {
  PEPROCESS process;
  HANDLE pid;
};

OB_PREOP_CALLBACK_STATUS preOperationCallback(
    PVOID registrationContext,
    POB_PRE_OPERATION_INFORMATION operationInformation);
NTSTATUS registryCallback(
    PVOID context,
    PVOID arg1,
    PVOID arg2);

BOOLEAN isProtectedServiceName(PCUNICODE_STRING serviceName);
BOOLEAN isProtectedServiceKey(PCUNICODE_STRING keyPath);

NTSTATUS registerProcessProtection();
NTSTATUS registerRegistryProtection(PDRIVER_OBJECT driverObject);

void setServiceProcess(PEPROCESS process);
[[nodiscard]] bool tryGetProtectedService(ProtectedServiceInfo &info);
[[nodiscard]] bool isProtectedServiceCaller();

void clearServiceProcess();

void unregisterProcessProtection();
void unregisterRegistryProtection();
} // namespace ServiceProtection