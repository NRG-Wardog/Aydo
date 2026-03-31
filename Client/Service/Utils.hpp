#pragma once

#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Utils {
std::vector<uint8_t> readFile(const std::string &path);

// Returns true if path looks like an NT device path: \Device\... or \??\...
bool is_nt_device_path(const std::wstring &p);

// Returns true if path looks like a DOS path: C:\...
bool is_dos_path(const std::wstring &p);

// Convert \Device\HarddiskVolumeX\... (or \??\C:\...) to DOS form (C:\...).
// If no mapping is found, returns the input unchanged.
std::wstring device_to_dos_path(const std::wstring &devicePath);

// Try to resolve using only the image string provided by the driver.
// - If it is already a DOS path, returns it.
// - If it is an NT device path, converts to DOS and returns it.
// - If it is only a base name (e.g. "notepad.exe"), returns std::nullopt.
std::optional<std::wstring> resolve_from_image_only(const std::wstring &imageFromDriver);

// Resolve full image path from a PID using Windows APIs.
// Returns std::nullopt on failure (e.g., access denied or process already exited).
std::optional<std::wstring> full_image_path_from_pid(DWORD pid);

// Robust resolver:
// 1) If imageFromDriver is full path (DOS or NT), normalize to DOS and return.
// 2) Else query by PID to get the true path.
// 3) Else return imageFromDriver (likely a base name).
std::wstring resolve_process_path(DWORD pid, const std::wstring &imageFromDriver);

// UTF-16 (std::wstring) to UTF-8 (std::string). Returns empty string if input empty.
std::string wstring_to_utf8(const std::wstring &w);
std::string wstring_to_utf8(const wchar_t *w);

// UTF-8 (std::string) to UTF-16 (std::wstring). Returns empty string if input empty.
std::wstring utf8_to_wstring(const std::string &s);
std::wstring utf8_to_wstring(const char *s);

// compute SHA-256 incrementally
std::string computeSHA256(const std::string &path);

double calculateEntropy(const std::vector<int> &countedBytes, std::streamsize totalLength);

// Check if a file is digitally signed by Microsoft/Windows
bool isWindowsSigned(const std::string &path);

// Quarantine a file (moves to ./quarantine relative to service)
bool quarantineFile(const std::string &path);

// Delete a file
bool deleteFile(const std::string &path);

} // namespace Utils
