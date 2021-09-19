#include "master.h"

BOOL GetSid(PWSTR* sid)
{
	BOOL status = FALSE;
	HANDLE hToken;
	DWORD cbNeed;
	PTOKEN_USER pTokenUser = NULL;

	if (OpenProcessToken((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &hToken))
	{
		if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &cbNeed) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
		{
			if (pTokenUser = LocalAlloc(LPTR, cbNeed))
			{
				if (GetTokenInformation(hToken, TokenUser, pTokenUser, cbNeed, &cbNeed))
				{
					if (ConvertSidToStringSidW(pTokenUser->User.Sid, sid))
						status = TRUE;
				}
				LocalFree(pTokenUser);
			}
		}
		CloseHandle(hToken);
	}

	return status;
}
BOOL GetGuidMasetKey(PWSTR* guid,PBYTE* masterKey,PDWORD dwMasterKey,PDWORD offset,PBYTE data)
{
	BOOL status = FALSE;
	DWORD len;
	
	len = *(PDWORD)data;
	*offset += sizeof(DWORD);

	if (*guid = LocalAlloc(LPTR, len + sizeof(wchar_t)))
	{
		RtlCopyMemory(*guid, data + *offset, len);
		*offset += len;
		len = *(PDWORD)(data + *offset);
		*offset += sizeof(DWORD);
		if (*masterKey = LocalAlloc(LPTR, len))
		{
			RtlCopyMemory(*masterKey, data + *offset, len);
			*dwMasterKey = len;
			*offset += len;
			status = TRUE;
		}
	}
	return status;
}
BOOL EncryptPassWord(PWSTR password,PBYTE* sha1Pass,PDWORD hashLen)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD PassLen = lstrlenW(password) * sizeof(wchar_t);

	if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
		{
			if (CryptHashData(hHash, (PBYTE)password, PassLen, 0))
			{
				if (CryptGetHashParam(hHash, HP_HASHVAL, NULL, hashLen, 0))
				{
					if (*sha1Pass = LocalAlloc(LPTR, *hashLen))
					{
						if (CryptGetHashParam(hHash, HP_HASHVAL, *sha1Pass, hashLen, 0))
						{
							status = TRUE;
						}
					}
				}
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}
BOOL EncryptHmac(PBYTE key, DWORD keyLen,PBYTE simessaged,DWORD messageLen,PBYTE* sha1DerivedKey,PDWORD dwsha1DerivedKey)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCRYPTHASH hHash;
	PGENERICKEY_BLOB keyBlob;
	HMAC_INFO HmacInfo = { CALG_SHA1, NULL, 0, NULL, 0 };
	DWORD szBlob = sizeof(GENERICKEY_BLOB) + keyLen;

	if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (keyBlob = (PGENERICKEY_BLOB)LocalAlloc(LPTR, szBlob))
		{
			keyBlob->Header.bType = PLAINTEXTKEYBLOB;
			keyBlob->Header.bVersion = CUR_BLOB_VERSION;
			keyBlob->Header.reserved = 0;
			keyBlob->Header.aiKeyAlg = CALG_RC2;
			keyBlob->dwKeyLen = keyLen;
			RtlCopyMemory((PBYTE)keyBlob + sizeof(GENERICKEY_BLOB), key, keyBlob->dwKeyLen);
			if (CryptImportKey(hProv, (LPCBYTE)keyBlob, szBlob, 0, CRYPT_IPSEC_HMAC_KEY, &hKey))
			{
				if (CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash))
				{
					if (CryptSetHashParam(hHash, HP_HMAC_INFO, (LPCBYTE)&HmacInfo, 0))
					{
						if (CryptHashData(hHash, (LPCBYTE)simessaged, messageLen, 0))
						{
							if (CryptGetHashParam(hHash, HP_HASHVAL, NULL, dwsha1DerivedKey, 0))
							{
								if (*sha1DerivedKey = (PBYTE)LocalAlloc(LPTR, *dwsha1DerivedKey))
								{
									if (CryptGetHashParam(hHash, HP_HASHVAL, *sha1DerivedKey, dwsha1DerivedKey, 0))
										status = TRUE;
								}
							}
						}
					}
					CryptDestroyKey(hHash);
				}
				CryptDestroyKey(hKey);
			}
			LocalFree(keyBlob);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}
DWORD Getcipherkeylen(ALG_ID hashId)
{
	DWORD len = 0, dwSize = sizeof(DWORD);
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptGenKey(hProv, hashId, 0, &hKey))
		{
			CryptGetKeyParam(hKey, KP_KEYLEN, (PBYTE)&len, &dwSize, 0);
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hProv, 0);
	}
	return len / 8;
}
DWORD Getcipherblocklen(ALG_ID hashId)
{
	DWORD len = 0, dwSize = sizeof(DWORD);
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptGenKey(hProv, hashId, 0, &hKey))
		{
			CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE)&len, &dwSize, 0);
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hProv, 0);
	}
	return len / 8;
}
BOOL kull_m_crypto_pkcs5_pbkdf2_hmac(LPVOID password, DWORD passwordLen, LPCVOID salt, DWORD saltLen, DWORD iterations, BYTE* key, DWORD keyLen)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD sizeHmac = 0, count, i, j, r, dwBuffer;
	PBYTE asalt, obuf, d1, buffer;

	if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
		{
			if (CryptGetHashParam(hHash, HP_HASHVAL, NULL, &sizeHmac, 0))
			{
				if (asalt = (PBYTE)LocalAlloc(LPTR, saltLen + sizeof(DWORD)))
				{
					if (obuf = (PBYTE)LocalAlloc(LPTR, sizeHmac))
					{
						if (d1 = (PBYTE)LocalAlloc(LPTR, sizeHmac))
						{
							status = TRUE;
							RtlCopyMemory(asalt, salt, saltLen);
							for (count = 1; keyLen > 0; count++)
							{
								*(PDWORD)(asalt + saltLen) = _byteswap_ulong(count);
								if (EncryptHmac(password, passwordLen, asalt, saltLen + 4, &buffer, &dwBuffer))
								{
									RtlCopyMemory(obuf, buffer, dwBuffer);
									RtlCopyMemory(d1, buffer, dwBuffer);
									LocalFree(buffer);

									for (i = 1; i < iterations; i++)
									{
										if (EncryptHmac(password, passwordLen, d1, sizeHmac, &buffer, &dwBuffer))
										{
											RtlCopyMemory(d1, buffer, dwBuffer);
											for(j=0;j< sizeHmac;j++)
												obuf[j] ^= d1[j];
											RtlCopyMemory(d1, obuf, sizeHmac);
											LocalFree(buffer);
										}
									}
									r = min(keyLen, sizeHmac);
									RtlCopyMemory(key, obuf, r);
									key += r;
									keyLen -= r;
								}
							}
							LocalFree(d1);
						}
						LocalFree(obuf);
					}
					LocalFree(asalt);
				}
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}

	return status;
}
PWSTR kull_m_string_getRandomGUID()
{
	UNICODE_STRING uString;
	GUID guid;
	PWSTR buffer = NULL;
	if (NT_SUCCESS(UuidCreate(&guid)))
	{
		if (NT_SUCCESS(RtlStringFromGUID(&guid, &uString)))
		{
			if (buffer = (PWSTR)LocalAlloc(LPTR, uString.MaximumLength))
				RtlCopyMemory(buffer, uString.Buffer, uString.MaximumLength);
			RtlFreeUnicodeString(&uString);
		}
	}
	return buffer;
}
BOOL kull_m_crypto_CryptGetProvParam(HCRYPTPROV hProv, DWORD dwParam, BOOL withError, PBYTE* data, OPTIONAL DWORD* cbData, OPTIONAL DWORD* simpleDWORD)
{
	BOOL status = FALSE;
	DWORD dwSizeNeeded;

	if (simpleDWORD)
	{
		dwSizeNeeded = sizeof(DWORD);
		if (CryptGetProvParam(hProv, dwParam, (BYTE*)simpleDWORD, &dwSizeNeeded, 0))
			status = TRUE;
	}
	else
	{
		if (CryptGetProvParam(hProv, dwParam, NULL, &dwSizeNeeded, 0))
		{
			if (*data = (PBYTE)LocalAlloc(LPTR, dwSizeNeeded))
			{
				if (CryptGetProvParam(hProv, dwParam, *data, &dwSizeNeeded, 0))
				{
					if (cbData)
						*cbData = dwSizeNeeded;
					status = TRUE;
				}
				else
				{

					*data = (PBYTE)LocalFree(*data);
				}
			}
		}

	}
	return status;
}
BOOL kull_m_crypto_close_hprov_delete_container(HCRYPTPROV hProv)
{
	BOOL status = FALSE;
	DWORD provtype;
	PSTR container = NULL, provider = NULL;
	if (kull_m_crypto_CryptGetProvParam(hProv, PP_CONTAINER, FALSE, (PBYTE*)&container, NULL, NULL))
	{
		if (kull_m_crypto_CryptGetProvParam(hProv, PP_NAME, FALSE, (PBYTE*)&provider, NULL, NULL))
		{
			if (kull_m_crypto_CryptGetProvParam(hProv, PP_PROVTYPE, FALSE, NULL, NULL, &provtype))
			{
				CryptReleaseContext(hProv, 0);
				status = CryptAcquireContextA(&hProv, container, provider, provtype, CRYPT_DELETEKEYSET);
			}
			LocalFree(provider);
		}
		LocalFree(container);
	}

	return status;
}

BOOL kull_m_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY* hSessionKey, HCRYPTPROV* hSessionProv)
{
	BOOL status = FALSE;
	PBYTE keyblob, pbSessionBlob, ptr;
	DWORD dwkeyblob, dwLen, i;
	PWSTR container;
	HCRYPTKEY hPrivateKey;

	if (container = kull_m_string_getRandomGUID())
	{
		if (CryptAcquireContextW(hSessionProv, container, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
		{
			hPrivateKey = 0;
			if (CryptGenKey(*hSessionProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE | (RSA1024BIT_KEY / 2), &hPrivateKey)) // 1024
			{
				if (CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob))
				{
					if (keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
					{
						if (CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob))
						{
							CryptDestroyKey(hPrivateKey);
							hPrivateKey = 0;

							dwLen = ((RSAPUBKEY*)(keyblob + sizeof(PUBLICKEYSTRUC)))->bitlen / 8;
							((RSAPUBKEY*)(keyblob + sizeof(PUBLICKEYSTRUC)))->pubexp = 1;
							ptr = keyblob + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY);

							ptr += 2 * dwLen; // Skip pubexp, modulus, prime1, prime2
							*ptr = 1; // Convert exponent1 to 1
							RtlZeroMemory(ptr + 1, dwLen / 2 - 1);
							ptr += dwLen / 2; // Skip exponent1
							*ptr = 1; // Convert exponent2 to 1
							RtlZeroMemory(ptr + 1, dwLen / 2 - 1);
							ptr += dwLen; // Skip exponent2, coefficient
							*ptr = 1; // Convert privateExponent to 1
							RtlZeroMemory(ptr + 1, (dwLen / 2) - 1);

							if (CryptImportKey(*hSessionProv, keyblob, dwkeyblob, 0, 0, &hPrivateKey))
							{
								dwkeyblob = (1024 / 2 / 8) + sizeof(ALG_ID) + sizeof(BLOBHEADER); // 1024
								if (pbSessionBlob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
								{
									((BLOBHEADER*)pbSessionBlob)->bType = SIMPLEBLOB;
									((BLOBHEADER*)pbSessionBlob)->bVersion = CUR_BLOB_VERSION;
									((BLOBHEADER*)pbSessionBlob)->reserved = 0;
									((BLOBHEADER*)pbSessionBlob)->aiKeyAlg = calgid;
									ptr = pbSessionBlob + sizeof(BLOBHEADER);
									*(ALG_ID*)ptr = CALG_RSA_KEYX;
									ptr += sizeof(ALG_ID);

									for (i = 0; i < keyLen; i++)
										ptr[i] = ((LPCBYTE)key)[keyLen - i - 1];
									ptr += (keyLen + 1);
									for (i = 0; i < dwkeyblob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + keyLen + 3); i++)
										if (ptr[i] == 0) ptr[i] = 0x42;
									pbSessionBlob[dwkeyblob - 2] = 2;

									status = CryptImportKey(*hSessionProv, pbSessionBlob, dwkeyblob, hPrivateKey, flags, hSessionKey);
									LocalFree(pbSessionBlob);
								}
							}
						}
						LocalFree(keyblob);
					}
				}
			}
			if (hPrivateKey)
				CryptDestroyKey(hPrivateKey);
			if (!status)
				kull_m_crypto_close_hprov_delete_container(*hSessionProv);
		}
		LocalFree(container);
	}
	return status;
}
BOOL ProtectMasterKey(PKULL_M_DPAPI_MASTERKEY masterkey,PBYTE shaDerivedkey,DWORD shaDerivedkeyLen,PBYTE pbKey, DWORD dwKey)
{
	BOOL status = FALSE;
	DWORD KeyLen, HMACLen = 20, BlockLen, dwBuffer;
	PBYTE buffer, tempKey, HMACHash;
	HCRYPTKEY hSessionKey;
	HCRYPTPROV hSessionProv;

	KeyLen = Getcipherkeylen(masterkey->algCrypt);
	BlockLen = Getcipherblocklen(masterkey->algCrypt);
	HMACLen += HMACLen % BlockLen;
	masterkey->__dwKeyLen = 16 + HMACLen + dwKey;

	if (masterkey->pbKey = (PBYTE)LocalAlloc(LPTR, masterkey->__dwKeyLen + BlockLen))
	{
		CDGenerateRandomBits(masterkey->pbKey, 16);
		if (tempKey = LocalAlloc(LPTR, HMACLen))
		{
			if (EncryptHmac(shaDerivedkey, shaDerivedkeyLen, masterkey->pbKey, 16, &buffer, &dwBuffer))
			{
				RtlCopyMemory(tempKey, buffer, dwBuffer);
				LocalFree(buffer);
				if (EncryptHmac(tempKey, HMACLen, pbKey, dwKey, &buffer, &dwBuffer))
				{
					RtlCopyMemory(masterkey->pbKey + 16, buffer, dwBuffer);
					RtlCopyMemory(masterkey->pbKey + 16 + HMACLen, pbKey, dwKey);
	
					if (HMACHash = LocalAlloc(LPTR, KeyLen + BlockLen))
					{
						if (kull_m_crypto_pkcs5_pbkdf2_hmac(shaDerivedkey, shaDerivedkeyLen, masterkey->salt, sizeof(masterkey->salt), masterkey->rounds, (PBYTE)HMACHash, KeyLen + BlockLen))
						{
							if (kull_m_crypto_hkey_session(masterkey->algCrypt, HMACHash, KeyLen, 0, &hSessionKey, &hSessionProv))
							{

								if (CryptSetKeyParam(hSessionKey, KP_IV, (PBYTE)HMACHash + KeyLen, 0))
								{
									if (status = CryptEncrypt(hSessionKey, 0, TRUE, 0, masterkey->pbKey, &masterkey->__dwKeyLen, masterkey->__dwKeyLen + BlockLen))
										masterkey->__dwKeyLen -= BlockLen;
								}
								CryptDestroyKey(hSessionKey);
								kull_m_crypto_close_hprov_delete_container(hSessionProv);
							}
						}
						LocalFree(HMACHash);
					}

					LocalFree(buffer);
				}

			}
			LocalFree(tempKey);
		}

		if (!status)
		{
			masterkey->pbKey = (PBYTE)LocalFree(masterkey->pbKey);
			masterkey->__dwKeyLen = 0;
		}
	}

	return status;
}
BOOL CreateMasterKey(PWSTR sid, PWSTR masterKeyFile,PWSTR guidName,PBYTE pkey,DWORD dwSize,PWSTR password)
{
	KULL_M_DPAPI_MASTERKEY masterkey = { 2, {0}, 4000, CALG_HMAC, CALG_3DES, NULL, 0 }; 
	KULL_M_DPAPI_MASTERKEYS masterkeys = { 2, 0, 0, {0}, 0, 0, 4, 0, 0, 0, 0, &masterkey, NULL, NULL, NULL };
	BOOL status = FALSE;
	UNICODE_STRING uString;
	GUID guid;
	DWORD dwSha1Pass, dwsha1DerivedKey, outLen;
	PBYTE sha1Pass, sha1DerivedKey, outMasterKeys;

	RtlInitUnicodeString(&uString, guidName);
	if (NT_SUCCESS(RtlGUIDFromString(&uString, &guid)))
	{
		CDGenerateRandomBits(masterkey.salt, sizeof(masterkey.salt));
		//RtlSecureZeroMemory(masterkey.salt, sizeof(masterkey.salt));
		RtlCopyMemory(masterkeys.szGuid, uString.Buffer + 1, uString.Length - 4);
		if (EncryptPassWord(password, &sha1Pass, &dwSha1Pass))
		{
			if (EncryptHmac(sha1Pass, dwSha1Pass, (PBYTE)sid, (lstrlenW(sid) + 1) * sizeof(wchar_t), &sha1DerivedKey, &dwsha1DerivedKey))
			{
				if (ProtectMasterKey(&masterkey, sha1DerivedKey, dwsha1DerivedKey, pkey, dwSize))
				{
					if (masterkey.pbKey)
					{
						outLen = FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey) + masterkey.__dwKeyLen;
						if (outMasterKeys = LocalAlloc(LPTR, outLen))
						{
							masterkeys.dwMasterKeyLen = masterkey.__dwKeyLen + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey);
							RtlCopyMemory(outMasterKeys, &masterkeys, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey));
					
							RtlCopyMemory(outMasterKeys + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey), &masterkey, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey));
							RtlCopyMemory(outMasterKeys + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey) + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) , masterkey.pbKey, masterkey.__dwKeyLen);
							WriteToFile(masterKeyFile, outMasterKeys, outLen);
							status = TRUE;
							LocalFree(outMasterKeys);
						}
						LocalFree(masterkey.pbKey);
					}
				}
				LocalFree(sha1DerivedKey);
			}
			LocalFree(sha1Pass);
		}
	}
	return status;
}
BOOL CreateMasterKeyLocalState(PWSTR sidFile,PWSTR lcoalstate,PWSTR password, PBYTE data,DWORD dwData,PDWORD dwFileSize)
{
	BOOL status = FALSE;
	PWSTR sid, guid;
	PBYTE masterKey;
	DWORD len = 0, offset = 0;
	wchar_t MasterKeyFile[MAX_PATH];
	wchar_t LocalState[MAX_PATH];
	wchar_t temp[40] = { 0 };

	
	if (GetSid(&sid))
	{
		if (GetGuidMasetKey(&guid, &masterKey, &len, &offset, data))
		{
			RtlCopyMemory(temp, guid + 1, (wcslen(guid) - 2) * sizeof(wchar_t));
			wsprintfW(MasterKeyFile, L"%ws\\%ws\\%ws", sidFile, sid, temp);
			if (CreateMasterKey(sid, MasterKeyFile, guid, masterKey, len, password))
			{

				wsprintfW(LocalState, L"%ws\\Local State", lcoalstate);
				len = *(PDWORD)(data + offset);
				offset += sizeof(DWORD);
				WriteToFile(LocalState, data + offset, len);
				offset += len;
				*dwFileSize = offset;
				status = TRUE;
			}
			LocalFree(guid);  
			LocalFree(masterKey);
		}
		LocalFree(sid);
	}
	return status;
}