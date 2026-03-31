#pragma once

#include <ntifs.h>

namespace Communications {
extern NTSTATUS handleKillProcessRequest(PIRP Irp);
extern NTSTATUS handleGetProcessNotificationRequest(PIRP Irp, ULONG *BytesReturned);
extern NTSTATUS handleRegisterService(PIRP Irp);
extern NTSTATUS handleGetProtectedPIDRequest(PIRP Irp, ULONG *BytesReturned);
extern NTSTATUS handleResumeProcessRequest(PIRP Irp);
NTSTATUS handleDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
} // namespace Communications
