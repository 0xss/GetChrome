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
#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define KULL_M_WIN_BUILD_VISTA	6000
#define KULL_M_WIN_BUILD_7		7600
#define KULL_M_WIN_BUILD_8		9200
#define KULL_M_WIN_BUILD_BLUE	9600
#define KULL_M_WIN_BUILD_10_1507	10240
#define KULL_M_WIN_BUILD_10_1511	10586
#define KULL_M_WIN_BUILD_10_1607	14393
#define KULL_M_WIN_BUILD_10_1703	15063
#define KULL_M_WIN_BUILD_10_1709	16299
#define KULL_M_WIN_BUILD_10_1803	17134
#define KULL_M_WIN_BUILD_10_1809	17763
#define KULL_M_WIN_BUILD_10_1903	18362
#define KULL_M_WIN_BUILD_10_1909	18363
#define KULL_M_WIN_BUILD_10_2004	19041
#define KULL_M_WIN_BUILD_10_20H2	19042
#define KULL_M_WIN_MIN_BUILD_11		22000

#define KULL_M_WIN_MIN_BUILD_VISTA	5000
#define KULL_M_WIN_MIN_BUILD_7		7000
#define KULL_M_WIN_MIN_BUILD_8		8000
#define KULL_M_WIN_MIN_BUILD_BLUE	9400
#define KULL_M_WIN_MIN_BUILD_10		9800

typedef struct _KULL_M_DPAPI_BLOB {
	DWORD	dwVersion;
	GUID	guidProvider;
	DWORD	dwMasterKeyVersion;
	GUID	guidMasterKey;
	DWORD	dwFlags;

	DWORD	dwDescriptionLen;
	PWSTR	szDescription;

	ALG_ID	algCrypt;
	DWORD	dwAlgCryptLen;

	DWORD	dwSaltLen;
	PBYTE	pbSalt;

	DWORD	dwHmacKeyLen;
	PBYTE	pbHmackKey;

	ALG_ID	algHash;
	DWORD	dwAlgHashLen;

	DWORD	dwHmac2KeyLen;
	PBYTE	pbHmack2Key;

	DWORD	dwDataLen;
	PBYTE	pbData;

	DWORD	dwSignLen;
	PBYTE	pbSign;
} KULL_M_DPAPI_BLOB, * PKULL_M_DPAPI_BLOB;
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,

	SystemProcessInformation = 5,

} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
} PROCESSINFOCLASS;
typedef struct _MASTERKEY_INFO
{
	PWSTR UserName;
	PWSTR sid;
	PWSTR guid;
	DWORD keyLen;
	PBYTE key;
}MASTERKEY_INFO, * PMASTERKEY_INFO;
typedef struct _MASTERKEY_LIST
{
	LIST_ENTRY navigator;
	MASTERKEY_INFO masterkey;
}MASTERKEY_LIST, * PMASTERKEY_LIST;
NTSTATUS WINAPI		NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT OPTIONAL PULONG ReturnLength);
NTSTATUS WINAPI		NtQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, OUT ULONG ProcessInformationLength, OUT OPTIONAL PULONG ReturnLength);
NTSTATUS WINAPI		RtlStringFromGUID(IN LPCGUID Guid, PUNICODE_STRING UnicodeString);
NTSTATUS NTAPI		RtlCompressBuffer(USHORT CompressionFormatAndEngine,PUCHAR UncompressedBuffer,ULONG  UncompressedBufferSize,PUCHAR CompressedBuffer,ULONG  CompressedBufferSize,ULONG  UncompressedChunkSize,PULONG FinalCompressedSize,PVOID  WorkSpace);
NTSTATUS NTAPI		RtlGetCompressionWorkSpaceSize(USHORT CompressionFormatAndEngine,PULONG CompressBufferWorkSpaceSize,PULONG CompressFragmentWorkSpaceSize);
NTSTATUS WINAPI		RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState);
VOID	 WINAPI		RtlGetNtVersionNumbers(LPDWORD, LPDWORD, LPDWORD);
VOID	 WINAPI		RtlFreeUnicodeString(IN OUT PUNICODE_STRING UnicodeString);
BOOL GetMasterKey(PLIST_ENTRY masterkey);
