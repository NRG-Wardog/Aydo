#include "Utils.hpp"
#include <ntstatus.h>

#define PROCESS_TERMINATE (0x0001)

bool Utils::KillProcess(ULONG TargetPID) {
  KdPrint(("KillProcess called with TargetPID %d\n", TargetPID));

  PEPROCESS Process;
  HANDLE ProcessHandle;
  NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TargetPID, &Process);
  if (NT_SUCCESS(status)) {
    status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE, *PsProcessType, KernelMode, &ProcessHandle);

    if (NT_SUCCESS(status)) {
      KeAttachProcess((PRKPROCESS)Process);
      ZwTerminateProcess(ProcessHandle, 0);
      KeDetachProcess();
      ZwClose(ProcessHandle);
      ObDereferenceObject(Process);
    } else {
      KdPrint(("Failed to open process: %x\n", status));
      return false;
    }
  } else {
    KdPrint(("Failed to lookup process: %x\n", status));
    return false;
  }

  return true;
}
