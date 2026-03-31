#include "KernelCommunications.hpp"

#include "../../IOCTLs.hpp"

KernelCommunications::KernelCommunications()
    : m_hControlDevice(INVALID_HANDLE_VALUE)
    , m_hNotificationDevice(INVALID_HANDLE_VALUE) {
}

KernelCommunications::~KernelCommunications() {
  disconnect();
}

bool KernelCommunications::connect(const std::wstring &devicePath) {
  // Already connected
  if (isConnected()) {
    return true;
  }

  constexpr DWORD SHARED_ACCESS = FILE_SHARE_READ | FILE_SHARE_WRITE;

  m_hControlDevice = CreateFileW(
      devicePath.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      SHARED_ACCESS,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr);

  if (m_hControlDevice == INVALID_HANDLE_VALUE) {
    return false;
  }

  m_hNotificationDevice = CreateFileW(
      devicePath.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      SHARED_ACCESS,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr);

  if (m_hNotificationDevice == INVALID_HANDLE_VALUE) {
    CloseHandle(m_hControlDevice);
    m_hControlDevice = INVALID_HANDLE_VALUE;
    return false;
  }

  return true;
}

void KernelCommunications::disconnect() {
  if (m_hControlDevice != INVALID_HANDLE_VALUE) {
    CloseHandle(m_hControlDevice);
    m_hControlDevice = INVALID_HANDLE_VALUE;
  }

  if (m_hNotificationDevice != INVALID_HANDLE_VALUE) {
    CloseHandle(m_hNotificationDevice);
    m_hNotificationDevice = INVALID_HANDLE_VALUE;
  }
}

bool KernelCommunications::isConnected() const {
  return m_hControlDevice != INVALID_HANDLE_VALUE &&
         m_hNotificationDevice != INVALID_HANDLE_VALUE;
}

bool KernelCommunications::sendIoctl(HANDLE deviceHandle,
                                     DWORD ioctlCode,
                                     void *inputBuffer,
                                     DWORD inputSize,
                                     void *outputBuffer,
                                     DWORD outputSize,
                                     DWORD *bytesReturned) {
  if (deviceHandle == INVALID_HANDLE_VALUE) {
    return false;
  }

  DWORD bytesRet = 0;
  BOOL result = DeviceIoControl(
      deviceHandle,
      ioctlCode,
      inputBuffer,
      inputSize,
      outputBuffer,
      outputSize,
      &bytesRet,
      nullptr);

  if (bytesReturned != nullptr) {
    *bytesReturned = bytesRet;
  }

  return result != FALSE;
}

bool KernelCommunications::killProcess(ULONG processId) {
  IOCTL_KILL_PROCESS_INPUT input;
  input.ProcessId = processId;

  return sendIoctl(m_hControlDevice, IOCTL_KILL_PROCESS, &input, sizeof(input), nullptr, 0);
}

bool KernelCommunications::resumeProcess(ULONG processId) {
  IOCTL_RESUME_PROCESS_INPUT input;
  input.ProcessId = processId;

  return sendIoctl(m_hControlDevice, IOCTL_RESUME_PROCESS, &input, sizeof(input), nullptr, 0);
}

std::optional<IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT> KernelCommunications::getProcessNotification() {
  IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT output;
  DWORD bytesReturned = 0;

  if (sendIoctl(m_hNotificationDevice,
                IOCTL_GET_PROCESS_NOTIFICATION,
                nullptr,
                0,
                &output,
                sizeof(output),
                &bytesReturned) &&
      bytesReturned == sizeof(output)) {
    return output;
  }

  return std::nullopt;
}

bool KernelCommunications::registerSelfAsService() {
  return sendIoctl(m_hControlDevice, IOCTL_REGISTER_SERVICE, nullptr, 0, nullptr, 0);
}