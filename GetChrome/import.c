
#include "global.h"
BOOL GetFile(PWSTR fileName, PBYTE* buffer, PDWORD dwFile)
{
	BOOL status = FALSE;
	HANDLE hFile = NULL;
	DWORD readed;

	*buffer = NULL;
	hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile && hFile != INVALID_HANDLE_VALUE)
	{
		*dwFile = GetFileSize(hFile, NULL);
		if (*buffer = LocalAlloc(LPTR, *dwFile))
		{
			if (ReadFile(hFile, *buffer, *dwFile, &readed, NULL))
				status = TRUE;
		}
		CloseHandle(hFile);
	}
	return status;
}
void WriteToFile(PWSTR fileNmae, PBYTE buffer, DWORD dwBuffer)
{
	HANDLE hFile = NULL;
	DWORD wrote;

	hFile = CreateFileW(fileNmae, GENERIC_WRITE, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile && hFile != INVALID_HANDLE_VALUE)
	{
		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
		SetEndOfFile(hFile);
		WriteFile(hFile, buffer, dwBuffer, &wrote, NULL);
		CloseHandle(hFile);
	}
}
NTSTATUS DeCompressData(PWSTR fileName,PBYTE* out,PDWORD dwOut)
{
	NTSTATUS status = STATUS_BAD_COMPRESSION_BUFFER;
	PBYTE buffer, CompressedBuffer = NULL;
	DWORD dwBuffer, CompressedBufferSize, FinalUncompressedSize;

	if (GetFile(fileName, &buffer, &dwBuffer))
	{

		for (CompressedBufferSize = dwBuffer; (status == STATUS_BAD_COMPRESSION_BUFFER) && (CompressedBuffer = LocalAlloc(LPTR, CompressedBufferSize)); CompressedBufferSize <<= 1)
		{
			status = RtlDecompressBuffer(COMPRESSION_FORMAT_XPRESS, CompressedBuffer, CompressedBufferSize, buffer, dwBuffer, &FinalUncompressedSize);
			if (!NT_SUCCESS(status))
				LocalFree(CompressedBuffer);
		}
		if (NT_SUCCESS(status))
		{
			*out = CompressedBuffer;
			*dwOut = FinalUncompressedSize;
		}
		else wprintf(L"[-] RtlDecompressBuffer Failed 0x%08x\n", status);
		LocalFree(buffer);
	}

	return status;
}

BOOL CheckChrome()
{
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	PSYSTEM_PROCESS_INFORMATION buffer = NULL, tokenInfo;
	DWORD sizeOfBuffer;
	BOOL result = TRUE;

	for (sizeOfBuffer = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (buffer = LocalAlloc(LPTR, sizeOfBuffer));)
	{
		status = NtQuerySystemInformation(SystemProcessInformation, buffer, sizeOfBuffer, &sizeOfBuffer);
		if (!NT_SUCCESS(status))
			LocalFree(buffer);
	}
	if (NT_SUCCESS(status))
	{
		for (tokenInfo = buffer; tokenInfo->NextEntryOffset; tokenInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)tokenInfo + tokenInfo->NextEntryOffset))
		{
			if (tokenInfo->ImageName.Length)
			{
				if (StrStrIW(tokenInfo->ImageName.Buffer, L"chrome.exe"))
				{
					result = FALSE;
					break;
				}
			}
		}
		LocalFree(buffer);
	}
	return result;
}
void ExportData(PWSTR DefaultPath, PBYTE data, DWORD dwData)
{
	DWORD offset = 0, dwFileName, dwBuffer;
	PWSTR FileName;
	PBYTE buffer;
	wchar_t FilePath[MAX_PATH];

	while (offset < dwData)
	{
		RtlSecureZeroMemory(FilePath, sizeof(FilePath));
		dwFileName = *(PDWORD)(data + offset);
		offset += sizeof(DWORD);
		if (FileName = LocalAlloc(LPTR, dwFileName + sizeof(wchar_t)))
		{
			RtlCopyMemory(FileName, data + offset, dwFileName);
			offset += dwFileName;
			dwBuffer = *(PDWORD)(data + offset);
			offset += sizeof(DWORD);
			if (buffer = LocalAlloc(LPTR, dwBuffer))
			{
				wsprintfW(FilePath, L"%ws\\%ws", DefaultPath, FileName);
				RtlCopyMemory(buffer, data + offset, dwBuffer);
				offset += dwBuffer;
				WriteToFile(FilePath, buffer, dwBuffer);
				LocalFree(buffer);
			}
			LocalFree(FileName);
		}
	}
	wprintf(L"[*] All File Saved :)\n");
}
int wmain(int argc, wchar_t** argv)
{
	PBYTE data;
	DWORD dwData;
	DWORD offset = 0;
	PWSTR temp;
	wchar_t ProtectPath[MAX_PATH];
	wchar_t GooglePath[MAX_PATH];
	wchar_t ProfileName[20] = { 0 };

	if (argc != 3)
	{
		wprintf(L"[*] Using %ws CompressFile CurrentUserPassword\n", argv[0]);
		ExitProcess(0);
	}
	if (CheckChrome())
	{
		if (NT_SUCCESS(DeCompressData(argv[1], &data, &dwData)))
		{
			if (temp = wcschr(argv[1], L'_'))
			{
				wsprintfW(ProfileName, L"%ws", temp + 1);
				GetEnvironmentVariableW(L"LocalAppData", GooglePath, MAX_PATH);
				GetEnvironmentVariableW(L"APPDATA", ProtectPath, MAX_PATH);
				wsprintfW(GooglePath, L"%ws\\Google\\Chrome\\User Data", GooglePath);
				wsprintfW(ProtectPath, L"%ws\\Microsoft\\Protect", ProtectPath);
				if (CreateMasterKeyLocalState(ProtectPath, GooglePath, argv[2], data, dwData, &offset))
				{
					wsprintfW(GooglePath, L"%ws\\%ws", GooglePath, ProfileName);
					if (!PathFileExistsW(GooglePath))
					{
						CreateDirectoryW(GooglePath, NULL);
					}
					ExportData(GooglePath, data + offset, dwData - offset);
				}
			}
			else wprintf(L"[-] CompressFile Name Error\n");
			LocalFree(data);
		}
	}
	else wprintf(L"[*] Need Close Chrome First\n");
	return 0;
}