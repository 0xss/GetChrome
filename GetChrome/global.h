#pragma once
#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <sspi.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <shlwapi.h>
#include <sddl.h>


#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"User32.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"cryptdll.lib")
#pragma comment(lib,"Rpcrt4.lib")
#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,

	SystemProcessInformation = 5,

} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, * PGENERICKEY_BLOB;
typedef LONG KPRIORITY;
typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS* PVM_COUNTERS;
typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
typedef enum _KWAIT_REASON {
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
	MaximumWaitReason
} KWAIT_REASON;
typedef struct _SYSTEM_THREAD {
#if !defined(_M_X64) || !defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER KernelTime;
#endif
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG State;
	KWAIT_REASON WaitReason;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER unk;
#endif
} SYSTEM_THREAD, * PSYSTEM_THREAD;
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE ParentProcessId;
	ULONG HandleCount;
	LPCWSTR Reserved2[2];
	ULONG PrivatePageCount;
	VM_COUNTERS VirtualMemoryCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD Threads[ANYSIZE_ARRAY];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
typedef struct _KULL_M_DPAPI_MASTERKEY {
	DWORD	dwVersion;
	BYTE	salt[16];
	DWORD	rounds;
	ALG_ID	algHash;
	ALG_ID	algCrypt;
	PBYTE	pbKey;
	DWORD	__dwKeyLen;
} KULL_M_DPAPI_MASTERKEY, * PKULL_M_DPAPI_MASTERKEY;
typedef struct _KULL_M_DPAPI_MASTERKEY_CREDHIST {
	DWORD	dwVersion;
	GUID	guid;
} KULL_M_DPAPI_MASTERKEY_CREDHIST, * PKULL_M_DPAPI_MASTERKEY_CREDHIST;

typedef struct _KULL_M_DPAPI_MASTERKEY_DOMAINKEY {
	DWORD	dwVersion;
	DWORD	dwSecretLen;
	DWORD	dwAccesscheckLen;
	GUID	guidMasterKey;
	PBYTE	pbSecret;
	PBYTE	pbAccesscheck;
} KULL_M_DPAPI_MASTERKEY_DOMAINKEY, * PKULL_M_DPAPI_MASTERKEY_DOMAINKEY;

typedef struct _KULL_M_DPAPI_MASTERKEYS {
	DWORD	dwVersion;
	DWORD	unk0;
	DWORD	unk1;
	WCHAR	szGuid[36];
	DWORD	unk2;
	DWORD	unk3;
	DWORD	dwFlags;
	DWORD64	dwMasterKeyLen;
	DWORD64 dwBackupKeyLen;
	DWORD64 dwCredHistLen;
	DWORD64	dwDomainKeyLen;
	PKULL_M_DPAPI_MASTERKEY	MasterKey;
	PKULL_M_DPAPI_MASTERKEY	BackupKey;
	PKULL_M_DPAPI_MASTERKEY_CREDHIST	CredHist;
	PKULL_M_DPAPI_MASTERKEY_DOMAINKEY	DomainKey;
} KULL_M_DPAPI_MASTERKEYS, * PKULL_M_DPAPI_MASTERKEYS;

NTSTATUS WINAPI		NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT OPTIONAL PULONG ReturnLength);
NTSTATUS WINAPI		RtlStringFromGUID(IN LPCGUID Guid, PUNICODE_STRING UnicodeString);
NTSTATUS WINAPI		RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState);
NTSTATUS NTAPI		RtlDecompressBuffer(USHORT CompressionFormat,PUCHAR UncompressedBuffer,ULONG  UncompressedBufferSize,PUCHAR CompressedBuffer,ULONG  CompressedBufferSize,PULONG FinalUncompressedSize);
VOID	 WINAPI		RtlGetNtVersionNumbers(LPDWORD, LPDWORD, LPDWORD);
VOID	 WINAPI		RtlFreeUnicodeString(IN OUT PUNICODE_STRING UnicodeString);
VOID	 WINAPI		RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);
NTSTATUS WINAPI		RtlGUIDFromString(IN PUNICODE_STRING GuidString, OUT GUID* Guid);
NTSTATUS WINAPI		CDGenerateRandomBits(LPVOID pbBuffer, ULONG cbBuffer);


void WriteToFile(PWSTR fileNmae, PBYTE buffer, DWORD dwBuffer);
BOOL CreateMasterKeyLocalState(PWSTR sidFile, PWSTR lcoalstate, PWSTR password, PBYTE data, DWORD dwData, PDWORD dwFileSize);