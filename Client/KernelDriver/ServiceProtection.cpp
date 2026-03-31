#include "ServiceProtection.hpp"

#include <ntifs.h>
#include "Constants.hpp"
#include "Logger.hpp"
#include "Utils.hpp"

namespace ServiceProtection {
PVOID g_registrationHandle = nullptr;
HANDLE g_servicePID = nullptr;
PEPROCESS g_serviceProcess = nullptr;
KSPIN_LOCK g_serviceLock;
BOOLEAN g_isInitialized = FALSE;
LARGE_INTEGER g_RegCookie = {0};

bool tryGetProtectedService(ProtectedServiceInfo &info) {
  KIRQL oldIrql;
  KeAcquireSpinLock(&g_serviceLock, &oldIrql);
  info.process = g_serviceProcess;
  info.pid = g_servicePID;
  KeReleaseSpinLock(&g_serviceLock, oldIrql);
  return info.process != nullptr;
}

bool isProtectedServiceCaller() {
  ProtectedServiceInfo info{};
  if (!tryGetProtectedService(info)) {
    return false;
  }
  return PsGetCurrentProcessId() == info.pid;
}

OB_PREOP_CALLBACK_STATUS preOperationCallback(
    PVOID registrationContext,
    POB_PRE_OPERATION_INFORMATION operationInformation) {
  UNREFERENCED_PARAMETER(registrationContext);

  ProtectedServiceInfo info{};
  if (!tryGetProtectedService(info) || info.process == nullptr) {
    return OB_PREOP_SUCCESS;
  }

  PEPROCESS targetProcess = nullptr;

  if (operationInformation->ObjectType == *PsProcessType) {
    targetProcess = (PEPROCESS)operationInformation->Object;
  } else if (operationInformation->ObjectType == *PsThreadType) {
    targetProcess = IoThreadToProcess((PETHREAD)operationInformation->Object);
  }

  if (targetProcess != info.process) {
    return OB_PREOP_SUCCESS;
  }

  if (PsGetCurrentProcess() == info.process) {
    return OB_PREOP_SUCCESS;
  }

  if (operationInformation->Operation == OB_OPERATION_HANDLE_CREATE ||
      operationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {

    if (operationInformation->ObjectType == *PsProcessType) {
      operationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(
          PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
          PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME);
    } else {
      operationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(
          THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT);
    }
  }

  return OB_PREOP_SUCCESS;
}

BOOLEAN isProtectedServiceKey(PCUNICODE_STRING keyPath) {
  if (!Utils::isValidUnicodeString(keyPath)) {
    return FALSE;
  }

  const ULONG arraySize = sizeof(Constants::PROTECTED_REGISTRY_PATHS) / sizeof(Constants::PROTECTED_REGISTRY_PATHS[0]);
  for (ULONG i = 0; i < arraySize; ++i) {
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, Constants::PROTECTED_REGISTRY_PATHS[i]);

    // Exact match or Prefix match
    if (RtlEqualUnicodeString(keyPath, &us, TRUE) || RtlPrefixUnicodeString(&us, keyPath, TRUE)) {
      return TRUE;
    }
  }

  return FALSE;
}

BOOLEAN isProtectedServiceName(PCUNICODE_STRING serviceName) {
  if (!Utils::isValidUnicodeString(serviceName)) {
    return FALSE;
  }

  for (ULONG i = 0; i < RTL_NUMBER_OF(Constants::PROTECTED_SERVICE_NAMES); ++i) {
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, Constants::PROTECTED_SERVICE_NAMES[i]);

    if (RtlEqualUnicodeString(serviceName, &us, TRUE)) {
      return TRUE;
    }
  }

  return FALSE;
}

BOOLEAN isProtectedRegistryObject(LARGE_INTEGER cookie, PVOID regObject) {
  PCUNICODE_STRING keyPath = nullptr;
  NTSTATUS status = CmCallbackGetKeyObjectIDEx(
      &cookie,
      regObject,
      nullptr,
      &keyPath,
      0);

  if (!NT_SUCCESS(status) || keyPath == nullptr) {
    return FALSE;
  }

  BOOLEAN isProtected = isProtectedServiceKey(keyPath);

  CmCallbackReleaseKeyObjectIDEx(keyPath);

  return isProtected;
}
NTSTATUS registryCallback(PVOID context, PVOID arg1, PVOID arg2) {
  UNREFERENCED_PARAMETER(context);

  auto notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)arg1;

  auto denyIfProtected =
      [&](PVOID object, const char *message, bool allowServiceProcess = false) -> NTSTATUS {
    if (!isProtectedRegistryObject(g_RegCookie, object)) {
      return STATUS_SUCCESS;
    }

    PEPROCESS callerProcess = PsGetCurrentProcess();

    if (allowServiceProcess && callerProcess == g_serviceProcess) {
      return STATUS_SUCCESS;
    }

    LOG_INFO(message);
    return STATUS_ACCESS_DENIED;
  };

  switch (notifyClass) {
  case RegNtPreOpenKeyEx: {
    auto info = (PREG_OPEN_KEY_INFORMATION_V1)arg2;

    if (info->CompleteName && info->CompleteName->Buffer) {
      if (isProtectedServiceKey(info->CompleteName)) {
        PEPROCESS callerProcess = PsGetCurrentProcess();

        if (callerProcess != g_serviceProcess) {
          if (info->DesiredAccess &
              (DELETE | WRITE_DAC | WRITE_OWNER | KEY_SET_VALUE)) {
            LOG_INFO("ServiceProtection: Blocked dangerous registry access to protected key");
            return STATUS_ACCESS_DENIED;
          }
        }
      }
    }
    break;
  }

  case RegNtPreSetValueKey: {
    auto info = (PREG_SET_VALUE_KEY_INFORMATION)arg2;
    return denyIfProtected(
        info->Object,
        "ServiceProtection: Blocked attempt to set value in protected key",
        true);
  }

  case RegNtPreDeleteValueKey: {
    auto info = (PREG_DELETE_VALUE_KEY_INFORMATION)arg2;
    return denyIfProtected(
        info->Object,
        "ServiceProtection: Blocked attempt to delete value in protected key");
  }

  case RegNtPreDeleteKey: {
    auto info = (PREG_DELETE_KEY_INFORMATION)arg2;
    return denyIfProtected(
        info->Object,
        "ServiceProtection: Blocked attempt to delete protected key");
  }

  case RegNtPreRenameKey: {
    auto info = (PREG_RENAME_KEY_INFORMATION)arg2;
    return denyIfProtected(
        info->Object,
        "ServiceProtection: Blocked attempt to rename protected key");
  }

  case RegNtPreSetInformationKey: {
    auto info = (PREG_SET_INFORMATION_KEY_INFORMATION)arg2;
    return denyIfProtected(
        info->Object,
        "ServiceProtection: Blocked attempt to modify protected key metadata");
  }

  default:
    break;
  }

  return STATUS_SUCCESS;
}

NTSTATUS registerProcessProtection() {
  if (g_isInitialized) {
    return STATUS_SUCCESS;
  }

  KeInitializeSpinLock(&g_serviceLock);

  OB_OPERATION_REGISTRATION opReg[2] = {0};
  OB_CALLBACK_REGISTRATION cbReg = {0};

  opReg[0].ObjectType = PsProcessType;
  opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
  opReg[0].PreOperation = preOperationCallback;

  opReg[1].ObjectType = PsThreadType;
  opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
  opReg[1].PreOperation = preOperationCallback;

  cbReg.Version = OB_FLT_REGISTRATION_VERSION;
  cbReg.OperationRegistrationCount = 2;
  cbReg.OperationRegistration = opReg;
  RtlInitUnicodeString(&cbReg.Altitude, Constants::ALTITUDE);
  cbReg.RegistrationContext = nullptr;

  NTSTATUS status = ObRegisterCallbacks(&cbReg, &g_registrationHandle);
  CHECK_NT_RETURN(status, "ServiceProtection: Failed to register process protection (0x%X)", status);

  g_isInitialized = TRUE;
  LOG_INFO("ServiceProtection: Process protection registered successfully");
  return status;
}

NTSTATUS registerRegistryProtection(PDRIVER_OBJECT driverObject) {
  UNICODE_STRING altitude;
  RtlInitUnicodeString(&altitude, Constants::ALTITUDE);

  NTSTATUS status = CmRegisterCallbackEx(
      registryCallback,
      &altitude,
      driverObject,
      nullptr,
      &g_RegCookie,
      nullptr);
  CHECK_NT_RETURN_CLEANUP(status, (g_RegCookie.QuadPart = 0), "ServiceProtection: CmRegisterCallbackEx failed (0x%X)", status);

  LOG_INFO("ServiceProtection: Registry callback registered successfully");
  return status;
}

void setServiceProcess(PEPROCESS process) {
  HANDLE pid = PsGetProcessId(process);
  LOG_DEBUG("Setting service process to PID %lu", (ULONG)(ULONG_PTR)pid);

  KIRQL oldIrql;
  KeAcquireSpinLock(&g_serviceLock, &oldIrql);

  if (g_serviceProcess != nullptr) {
    ObDereferenceObject(g_serviceProcess);
  }

  g_serviceProcess = process;
  g_servicePID = pid;
  if (process != nullptr) {
    ObReferenceObject(process);
  }

  KeReleaseSpinLock(&g_serviceLock, oldIrql);
}

void clearServiceProcess() {
  LOG_DEBUG("ServiceProtection: Clearing protected service process");

  KIRQL oldIrql;
  KeAcquireSpinLock(&g_serviceLock, &oldIrql);

  if (g_serviceProcess != nullptr) {
    ObDereferenceObject(g_serviceProcess);
    g_serviceProcess = nullptr;
  }
  g_servicePID = nullptr;

  KeReleaseSpinLock(&g_serviceLock, oldIrql);
}

void unregisterProcessProtection() {
  if (!g_isInitialized) {
    return;
  }

  clearServiceProcess();

  if (g_registrationHandle != nullptr) {
    ObUnRegisterCallbacks(g_registrationHandle);
    g_registrationHandle = nullptr;
    LOG_INFO("ServiceProtection: Object callbacks unregistered successfully");
  }

  g_isInitialized = FALSE;
}

void unregisterRegistryProtection() {
  if (g_RegCookie.QuadPart == 0) {
    return;
  }
  NTSTATUS status = CmUnRegisterCallback(g_RegCookie);
  if (NT_SUCCESS(status)) {
    LOG_INFO("ServiceProtection: Registry callback unregistered successfully");
  } else {
    LOG_ERROR("ServiceProtection: Failed to unregister registry callback: 0x%X",
              status);
  }
  g_RegCookie.QuadPart = 0;
}
} // namespace ServiceProtection