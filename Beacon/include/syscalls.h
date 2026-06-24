#pragma once

#include "resolver.h"
#include "utils.h"

enum class SYSCALLS_ID : uint32_t {
    HWSYSCALLS = 0,
    UNDEFINED = 1
};

extern "C" void setSyscallPivot(const char* pivot);

[[nodiscard]] bool DeinitHWSyscalls(functionTable* funcTable);

extern "C" [[nodiscard]] bool initSyscalls(SYSCALLS_ID ID);

[[nodiscard]] bool testSyscalls(void);
[[nodiscard]] bool testSyscalls(functionTable* funcTable);


/* Syscall Wrapper Functions - Much cleaner API! */
[[nodiscard]] NTSTATUS syscallNtClose(HANDLE Handle);
[[nodiscard]] NTSTATUS syscallNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
[[nodiscard]] NTSTATUS syscallNtDeleteFile(PCOBJECT_ATTRIBUTES ObjectAttributes);
[[nodiscard]] NTSTATUS syscallNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, PCOBJECT_ATTRIBUTES ProcessObjectAttributes, PCOBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
[[nodiscard]] NTSTATUS syscallNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
[[nodiscard]] NTSTATUS syscallNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
[[nodiscard]] NTSTATUS syscallNtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length, FSINFOCLASS FsInformationClass);
[[nodiscard]] NTSTATUS syscallNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
[[nodiscard]] NTSTATUS syscallNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
[[nodiscard]] NTSTATUS syscallNtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
[[nodiscard]] NTSTATUS syscallNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
[[nodiscard]] NTSTATUS syscallNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
[[nodiscard]] NTSTATUS syscallNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);
[[nodiscard]] NTSTATUS syscallNtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
[[nodiscard]] NTSTATUS syscallNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
[[nodiscard]] NTSTATUS syscallNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
[[nodiscard]] NTSTATUS syscallNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
[[nodiscard]] NTSTATUS syscallNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
[[nodiscard]] NTSTATUS syscallNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
[[nodiscard]] NTSTATUS syscallNtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
[[nodiscard]] NTSTATUS syscallNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
[[nodiscard]] NTSTATUS syscallNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
[[nodiscard]] NTSTATUS syscallNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE TokenHandle);
[[nodiscard]] NTSTATUS syscallNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
[[nodiscard]] NTSTATUS syscallNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
[[nodiscard]] NTSTATUS syscallLdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics, PCUNICODE_STRING DllName, PVOID* DllHandle);
[[nodiscard]] NTSTATUS syscallRtlRandomEx(PULONG Seed);
[[nodiscard]] NTSTATUS syscallNtInitiatePowerAction(POWER_ACTION SystemAction, SYSTEM_POWER_STATE LightestSystemState, ULONG Flags, BOOLEAN Asynchronous);
[[nodiscard]] NTSTATUS syscallNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
[[nodiscard]] PVOID    syscallRtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
[[nodiscard]] NTSTATUS syscallRtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
[[nodiscard]] NTSTATUS syscallRtlCreateProcessParametersEx(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
[[nodiscard]] NTSTATUS syscallNtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T RegionSize);
[[nodiscard]] NTSTATUS syscallNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);