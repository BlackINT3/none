/****************************************************************************
**
** Copyright (C) 2019 BlackINT3
** Contact: https://github.com/BlackINT3/none
**
** GNU Lesser General Public License Usage (LGPL)
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 or version 3 as published by the Free
** Software Foundation and appearing in the file LICENSE.LGPLv21 and
** LICENSE.LGPLv3 included in the packaging of this file. Please review the
** following information to ensure the GNU Lesser General Public License
** requirements will be met: https://www.gnu.org/licenses/lgpl.html and
** http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
****************************************************************************/
#include <Windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#pragma comment(lib, "Crypt32.lib")
#include <algorithm>
#include <tchar.h>
#include <common/unone-common.h>
#include <native/unone-native.h>
#include <internal/unone-internal.h>
#include <string/unone-str.h>
#include <os/unone-os.h>
#include <time/unone-tm.h>
#include "unone-se.h"

#ifndef WINTRUST_SIGNATURE_SETTINGS
typedef struct WINTRUST_SIGNATURE_SETTINGS_ {
	DWORD                  cbStruct;
	DWORD                  dwIndex;
	DWORD                  dwFlags;
	DWORD                  cSecondarySigs;
	DWORD                  dwVerifiedSigIndex;
	PVOID				 pCryptoPolicy;
} WINTRUST_SIGNATURE_SETTINGS, * PWINTRUST_SIGNATURE_SETTINGS;
//Verifies the signature specified in WINTRUST_SIGNATURE_SETTINGS.dwIndex
#define WSS_VERIFY_SPECIFIC         0x00000001  
//Puts count of secondary signatures in WINTRUST_SIGNATURE_SETTINGS.cSecondarySigs
#define WSS_GET_SECONDARY_SIG_COUNT 0x00000002
#endif

namespace {
enum PRIVILEGE_OPERATE {
	PRIVILEGE_UNKNOWN,
	PRIVILEGE_ENBALE,
	PRIVILEGE_DISABLE
};
bool OpProcessPrivilegeByApi(const wchar_t* priv_name, PRIVILEGE_OPERATE operate_type)
{
	typedef BOOL (WINAPI* __OpenProcessToken)(
		__in        HANDLE ProcessHandle,
		__in        DWORD DesiredAccess,
		__deref_out PHANDLE TokenHandle
		);
	typedef BOOL (WINAPI* __LookupPrivilegeValueW)(
		__in_opt LPCWSTR lpSystemName,
		__in     LPCWSTR lpName,
		__out    PLUID   lpLuid
		);
	typedef BOOL (WINAPI* __AdjustTokenPrivileges)(
		__in      HANDLE TokenHandle,
		__in      BOOL DisableAllPrivileges,
		__in_opt  PTOKEN_PRIVILEGES NewState,
		__in      DWORD BufferLength,
		__out_bcount_part_opt(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
		__out_opt PDWORD ReturnLength
		);
	bool result = false;
	HANDLE token;
	LUID name_value;
	TOKEN_PRIVILEGES tp;
	do {
		HMODULE advapi32 = GetModuleHandleW(L"advapi32.dll");
		if (advapi32 == NULL) {
			advapi32 = LoadLibraryW(L"advapi32.dll");
			if (advapi32 == NULL) break;
		}
		__OpenProcessToken pOpenProcessToken = (__OpenProcessToken)GetProcAddress(advapi32, "OpenProcessToken");
		__LookupPrivilegeValueW pLookupPrivilegeValueW = (__LookupPrivilegeValueW)GetProcAddress(advapi32, "LookupPrivilegeValueW");
		__AdjustTokenPrivileges pAdjustTokenPrivileges = (__AdjustTokenPrivileges)GetProcAddress(advapi32, "AdjustTokenPrivileges");
		if (pOpenProcessToken == NULL || pLookupPrivilegeValueW == NULL || pAdjustTokenPrivileges == NULL) {
			break;
		}
		if (!pOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &token)) {
			UNONE_ERROR("OpenProcessToken err:%d",GetLastError());
			break;
		}
		if (!pLookupPrivilegeValueW(NULL, priv_name, &name_value)) {
			UNONE_ERROR("LookupPrivilegeValueW err:%d",GetLastError());
			CloseHandle(token);
			break;
		}
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = name_value;
		if (operate_type == PRIVILEGE_ENBALE)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;
		if (!pAdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL) || 
			GetLastError() != ERROR_SUCCESS) {
			UNONE_ERROR("AdjustTokenPrivileges err:%d",GetLastError());
			CloseHandle(token); 
			break;
		}
		CloseHandle(token);
		result = true;
	} while(0);
	return result;
}

bool OpProcessPrivilegeByNative(DWORD priv_number, PRIVILEGE_OPERATE operate_type)
{
	NTSTATUS status;
	BOOLEAN enable;
	BOOLEAN was_enabled = FALSE;
	bool result = false;
	__RtlAdjustPrivilege pRtlAdjustPrivilege = NULL;
	do {
		pRtlAdjustPrivilege = (__RtlAdjustPrivilege)GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"), "RtlAdjustPrivilege");
		if (pRtlAdjustPrivilege == NULL) break;
		enable = (operate_type == PRIVILEGE_ENBALE);
		status = pRtlAdjustPrivilege(priv_number, enable, FALSE, &was_enabled);	//SE_DEBUG_PRIVILEGE=20
		if (!NT_SUCCESS(status)) {
			UNONE_ERROR("RtlAdjustPrivilege err:%x", status);
			break;
		}
		result = true;
	} while (0);
	return result;
}

bool GetCertInfo(HANDLE state_data, std::vector<UNONE::CertInfoW>& infos)
{
	HMODULE wintrust = GetModuleHandleW(L"wintrust.dll");
	if (wintrust == NULL) {
		wintrust = LoadLibraryW(L"wintrust.dll");
		if (wintrust == NULL) return false;
	}
	typedef CRYPT_PROVIDER_DATA* (WINAPI* __WTHelperProvDataFromStateData)(HANDLE hStateData);
	typedef DWORD (WINAPI* __CertGetNameStringA)(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void* pvTypePara, LPWSTR pszNameString, DWORD cchNameString);
	typedef PCCRYPT_OID_INFO (WINAPI* __CryptFindOIDInfo)(DWORD dwKeyType, void* pvKey, DWORD dwGroupId);
	auto pWTHelperProvDataFromStateData = (__WTHelperProvDataFromStateData)GetProcAddress(wintrust, "WTHelperProvDataFromStateData");
	if (!pWTHelperProvDataFromStateData) {
		return false;
	}

	do {
		HMODULE crypt32 = GetModuleHandleW(L"crypt32.dll");
		if (!crypt32) {
			crypt32 = LoadLibraryW(L"crypt32.dll");
			if (crypt32 == NULL) break;
		}
		auto pCertGetNameStringW = (__CertGetNameStringA)GetProcAddress(crypt32, "CertGetNameStringW");
		auto pCryptFindOIDInfo = (__CryptFindOIDInfo)GetProcAddress(crypt32, "CryptFindOIDInfo");
		if (!pCertGetNameStringW || !pCryptFindOIDInfo)
			break;

		PCRYPT_PROVIDER_DATA ProviderData = pWTHelperProvDataFromStateData(state_data);
		if (ProviderData == NULL || ProviderData->pasSigners == NULL || ProviderData->pasSigners->psSigner == NULL)
			break;

		for (auto signer = ProviderData->pasSigners; signer != NULL; signer = signer->pasCounterSigners) {
			UNONE::CertInfoW info;
			PCRYPT_INTEGER_BLOB serial = &signer->psSigner->SerialNumber;
			PCRYPT_ALGORITHM_IDENTIFIER hashalg = &signer->psSigner->HashAlgorithm;
			if (hashalg && hashalg->pszObjId) {
				PCCRYPT_OID_INFO coi = pCryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, hashalg->pszObjId, 0);
				if (coi && coi->pwszName) {
					info.hashalg = UNONE::StrFormatW(L"%ls", coi->pwszName);
				} else {
					info.hashalg = UNONE::StrFormatW(L"%hs", hashalg->pszObjId);
				}
			}
			info.sn = UNONE::StrToW(UNONE::StrStreamToHexStrA(std::string((char*)serial->pbData, serial->cbData)));
			info.date = UNONE::TmFormatSystemTimeW(UNONE::TmConvertZoneTime(UNONE::TmFileTimeToSystem(signer->sftVerifyAsOf), NULL), L"Y-M-D H:W:S");
			PCERT_SIMPLE_CHAIN chain = signer->pChainContext->rgpChain[0];
			PCCERT_CONTEXT ctx = chain->rgpElement[0]->pCertContext;
			DWORD size = pCertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
			auto owner = new(std::nothrow) WCHAR[size];
			if (owner) {
				pCertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, owner, size);
				info.owner = std::move(owner);
				delete[] owner;
			}
			infos.push_back(info);
			break;
		}
	} while (0);
	return true;
}

//refrence:
//https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Security/CodeSigning/cpp/codesigning.cpp
bool OpSignatureInfoW(const std::wstring &file, std::vector<UNONE::CertInfoW> &infos, bool revoked_check, bool only_verify)
{
	#define HCATADMIN	HANDLE	
	#define HCATINFO	HANDLE	
	typedef struct CATALOG_INFO_ {
		DWORD cbStruct;
		WCHAR wszCatalogFile[MAX_PATH];
	} CATALOG_INFO;
	typedef BOOL(WINAPI* __CryptCATAdminAcquireContext)(HCATADMIN* phCatAdmin, const GUID* pgSubsystem, DWORD dwFlags);
	typedef BOOL(WINAPI* __CryptCATAdminReleaseContext)(HCATADMIN catadmin, DWORD dwFlags);
	typedef BOOL(WINAPI* __CryptCATAdminCalcHashFromFileHandle)(HANDLE File, DWORD* pcbHash, BYTE* pbHash, DWORD dwFlags);
	typedef HCATINFO(WINAPI* __CryptCATAdminEnumCatalogFromHash)(HCATADMIN catadmin, BYTE* pbHash, DWORD cbHash, DWORD dwFlags, HCATINFO* phPrevCatInfo);
	typedef BOOL(WINAPI* __CryptCATAdminReleaseCatalogContext)(HCATADMIN catadmin, HCATINFO CatInfo, DWORD dwFlags);
	typedef BOOL(WINAPI* __CryptCATCatalogInfoFromContext)(HCATINFO CatInfo, CATALOG_INFO* psCatInfo, DWORD dwFlags);
	typedef LONG(WINAPI* __WinVerifyTrust)(HWND hWnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData);
	
	bool ret = false;
	HMODULE wintrust = GetModuleHandleW(L"wintrust.dll");
	if (wintrust == NULL) {
		wintrust = LoadLibraryW(L"wintrust.dll");
		if (wintrust == NULL) return false;
	}
	auto pCryptCATAdminAcquireContext = (__CryptCATAdminAcquireContext)GetProcAddress(wintrust, "CryptCATAdminAcquireContext");
	auto pCryptCATAdminReleaseContext = (__CryptCATAdminReleaseContext)GetProcAddress(wintrust, "CryptCATAdminReleaseContext");
	auto pCryptCATAdminCalcHashFromFileHandle = (__CryptCATAdminCalcHashFromFileHandle)GetProcAddress(wintrust, "CryptCATAdminCalcHashFromFileHandle");
	auto pCryptCATAdminEnumCatalogFromHash = (__CryptCATAdminEnumCatalogFromHash)GetProcAddress(wintrust, "CryptCATAdminEnumCatalogFromHash");
	auto pCryptCATAdminReleaseCatalogContext = (__CryptCATAdminReleaseCatalogContext)GetProcAddress(wintrust, "CryptCATAdminReleaseCatalogContext");
	auto pCryptCATCatalogInfoFromContext = (__CryptCATCatalogInfoFromContext)GetProcAddress(wintrust, "CryptCATCatalogInfoFromContext");
	auto pWinVerifyTrust = (__WinVerifyTrust)GetProcAddress(wintrust, "WinVerifyTrust");
	if (!pCryptCATAdminAcquireContext || !pCryptCATAdminReleaseContext || !pCryptCATAdminCalcHashFromFileHandle ||
		!pCryptCATAdminEnumCatalogFromHash || !pCryptCATAdminReleaseCatalogContext || !pCryptCATCatalogInfoFromContext ||
		!pWinVerifyTrust) {
		return false;
	}

	HCATADMIN catadmin = NULL;
	if (!pCryptCATAdminAcquireContext(&catadmin, NULL, 0))
		return false;

	HANDLE fd = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (fd == INVALID_HANDLE_VALUE) {
		UNONE_ERROR(L"CreateFileW file:%s err:%d", file.c_str(), GetLastError());
		pCryptCATAdminReleaseContext(catadmin, 0);
		return false;
	}

	HRESULT hr;
	DWORD err = ERROR_SUCCESS;
	WINTRUST_DATA *wd = new WINTRUST_DATA;
	HCATINFO catalog = NULL;
	GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	int wdsize = sizeof(WINTRUST_DATA);
#if _WIN32_WINNT <= 0x0601
	//WINTRUST_SIGNATURE_SETTINGS introduced in Win8
	if (UNONE::OsMajorVer() >= 6 && UNONE::OsMinorVer() >= 2 || UNONE::OsMajorVer()>=10) {
		wdsize = sizeof(WINTRUST_DATA) + sizeof(WINTRUST_SIGNATURE_SETTINGS*);
	}
#endif
	do {
		BYTE hash[64];
		DWORD hsize = 64;
		pCryptCATAdminCalcHashFromFileHandle(fd, &hsize, hash, 0);
		CloseHandle(fd);

		WINTRUST_FILE_INFO wfi = { 0 };
		WINTRUST_CATALOG_INFO wci = { 0 };
		CATALOG_INFO ci = { 0 };
		catalog = pCryptCATAdminEnumCatalogFromHash(catadmin, hash, hsize, 0, NULL);
		if (catalog == NULL) {
			wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
			wfi.pcwszFilePath = file.c_str();
			wfi.hFile = NULL;
			wfi.pgKnownSubject = NULL;
			wd->cbStruct = wdsize;
			wd->dwUnionChoice = WTD_CHOICE_FILE;
			wd->pFile = &wfi;
			wd->dwUIChoice = WTD_UI_NONE;
			wd->hWVTStateData = NULL;
			wd->pwszURLReference = NULL;
			wd->dwStateAction = WTD_STATEACTION_VERIFY;
			wd->fdwRevocationChecks = WTD_REVOKE_NONE;
			wd->dwProvFlags = revoked_check ? WTD_SAFER_FLAG : WTD_CACHE_ONLY_URL_RETRIEVAL;
		}	else {
			auto member_tag = UNONE::StrToW(UNONE::StrStreamToHexStrA(std::string((char*)hash, hsize)));
			pCryptCATCatalogInfoFromContext(catalog, &ci, 0);
			wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
			wci.pcwszCatalogFilePath = ci.wszCatalogFile;
			wci.pcwszMemberFilePath = file.c_str();
			wci.pcwszMemberTag = member_tag.c_str();
			wci.pbCalculatedFileHash = hash;
			wci.cbCalculatedFileHash = hsize;
			wd->cbStruct = wdsize;
			wd->dwUnionChoice = WTD_CHOICE_CATALOG;
			wd->pCatalog = &wci;
			wd->dwUIChoice = WTD_UI_NONE;
			wd->hWVTStateData = NULL;
			wd->pwszURLReference = NULL;
			wd->dwStateAction = WTD_STATEACTION_VERIFY;
			wd->fdwRevocationChecks = revoked_check ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
			wd->dwProvFlags = revoked_check ? 0 : WTD_CACHE_ONLY_URL_RETRIEVAL;
		}

		// multi signatures
		WINTRUST_SIGNATURE_SETTINGS wss = {0};
		wss.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
		wss.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC;
		wss.dwIndex = 0;

		WINTRUST_SIGNATURE_SETTINGS* pSignatureSettings;
#if _WIN32_WINNT <= 0x0601
		pSignatureSettings = *(WINTRUST_SIGNATURE_SETTINGS**)((char*)&wd->dwUIContext + sizeof(DWORD)) = &wss;
#else
		pSignatureSettings = wd->pSignatureSettings = &wss;
#endif

		hr = pWinVerifyTrust(NULL, &action, wd);
		ret = SUCCEEDED(hr);
		if (!ret) err = hr;
		if (only_verify) break;
		
		std::vector<UNONE::CertInfoW> temps;
		GetCertInfo(wd->hWVTStateData, temps);
		infos.insert(infos.end(), temps.begin(), temps.end());

		// Now attempt to verify all secondary signatures that were found
		for (DWORD i = 1; i <= pSignatureSettings->cSecondarySigs; i++) {
			temps.clear();
			wss.dwIndex = i;
			wd->hWVTStateData = NULL;
			hr = pWinVerifyTrust(NULL, &action, wd);
			ret = SUCCEEDED(hr);
			if (!ret) err = hr;
			GetCertInfo(wd->hWVTStateData, temps);
			infos.insert(infos.end(), temps.begin(), temps.end());
		}

	} while (0);

	//Free wd->hWVTStateData
	wd->dwStateAction = WTD_STATEACTION_CLOSE;
	hr = pWinVerifyTrust(NULL, &action, wd);
	if (catalog != NULL) pCryptCATAdminReleaseCatalogContext(catadmin, catalog, 0);
	pCryptCATAdminReleaseContext(catadmin, 0);

	if (!ret) SetLastError(err);
	return ret;
}

}

namespace UNONE {

/*++
Description:
	enable privilege
Arguments:
	priv_name - privilege name
	priv_number - privilege number
Return:
	bool
--*/
bool SeEnablePrivilegeA(__in const char* priv_name, __in DWORD priv_number)
{
	if (priv_name) {
		return SeEnablePrivilegeW(StrToW(priv_name).c_str(), priv_number);
	}
	return SeEnablePrivilegeW(NULL, priv_number);
}

/*++
Description:
	enable privilege
Arguments:
	priv_name - privilege name
	priv_number - privilege number
Return:
	bool
--*/
bool SeEnablePrivilegeW(__in const wchar_t* priv_name, __in DWORD priv_number)
{
	if (priv_name != NULL)
		return OpProcessPrivilegeByApi(priv_name, PRIVILEGE_ENBALE);
	else
		return OpProcessPrivilegeByNative(priv_number, PRIVILEGE_ENBALE);
}

/*++
Description:
	enable privilege
Arguments:
	priv_name - privilege name
	priv_number - privilege number
Return:
	bool
--*/
bool SeDisablePrivilegeA(__in const char* priv_name, __in DWORD priv_number)
{
	return SeDisablePrivilegeW(StrToW(priv_name).c_str(), priv_number);
}

/*++
Description:
	enable privilege
Arguments:
	priv_name - privilege name
	priv_number - privilege number
Return:
	bool
--*/
bool SeDisablePrivilegeW(__in const wchar_t* priv_name, __in DWORD priv_number)
{
	if (priv_name != NULL)
		return OpProcessPrivilegeByApi(priv_name, PRIVILEGE_DISABLE);
	else
		return OpProcessPrivilegeByNative(priv_number, PRIVILEGE_DISABLE);
}


/*++
Description:
	enable debug privilege
Arguments:
	natived - use native
Return:
	bool
--*/
bool SeEnableDebugPrivilege(__in bool natived)
{
	if (natived)
		return SeEnablePrivilege(NULL, SE_DEBUG_PRIVILEGE);
	else
		return SeEnablePrivilege(SE_DEBUG_NAME);
}

/*++
Description:
	disable debug privilege
Arguments:
	natived - use native
Return:
	bool
--*/
bool SeDisableDebugPrivilege(__in bool natived)
{
	if (natived)
		return SeDisablePrivilege(NULL, SE_DEBUG_PRIVILEGE);
	else
		return SeDisablePrivilege(SE_DEBUG_NAME);
}

/*++
Description:
	verify signature, if verify ok, return true, vice versa.
Arguments:
	file - file path
	revoked_check - revocation check
Return:
	bool
--*/
bool SeVerifyCertA(__in const std::string &file, __in bool revoked_check)
{
	return SeVerifyCertW(StrToW(file), revoked_check);
}

/*++
Description:
	verify signature, if verify ok, return true, vice versa.
Arguments:
	file - file path
	revoked_check - revocation check
Return:
	bool
--*/
bool SeVerifyCertW(__in const std::wstring &file, __in bool revoked_check)
{
	std::vector<UNONE::CertInfoW> infos;
	return OpSignatureInfoW(file, infos, revoked_check, true);
}

/*++
Description:
	verify Microsoft signature, if verify ok, return true, vice versa.
Arguments:
	file - file path
	revoked_check - revocation check
Return:
	bool
--*/
bool SeVerifyMicrosoftCertA(__in const std::string &file, __in bool revoked_check)
{
	return SeVerifyMicrosoftCertW(StrToW(file), revoked_check);
}

/*++
Description:
	verify Microsoft signature, if verify ok, return true, vice versa.
Arguments:
	file - file path
	revoked_check - revocation check
Return:
	bool
--*/
bool SeVerifyMicrosoftCertW(__in const std::wstring &file, __in bool revoked_check)
{
	std::vector<UNONE::CertInfoW> infos;
	auto ret = SeGetCertInfoW(file, infos, revoked_check);
	if (!ret)	return false;
	for (auto it = infos.begin(); it != infos.end(); it++) {
		if (UNONE::StrContainIW(it->owner, L"Microsoft"))
			return true;
	}
	return false;
}

/*++
Description:
	get certificate information, if verify ok, return true, vice versa.
Arguments:
	file - file path
	infos - certificate information
	revoked_check - revocation check
Return:
	bool
--*/
bool SeGetCertInfoA(__in const std::string &file, __out std::vector<UNONE::CertInfoA> &infos, __in bool revoked_check)
{
	bool ret = false;
	std::vector<UNONE::CertInfoW> w_infos;
	ret = SeGetCertInfoW(StrToW(file), w_infos, revoked_check);
	std::for_each(w_infos.begin(), w_infos.end(), [&infos](CertInfoW &ci) {
		CertInfoA info;
		info.sn = UNONE::StrToA(ci.sn);
		info.owner = UNONE::StrToA(ci.owner);
		infos.push_back(info);
	});
	return ret;
}

/*++
Description:
	get certificate information, if verify ok, return true, vice versa.
Arguments:
	file - file path
	infos - certificate information
	revoked_check - revocation check
Return:
	bool
--*/
bool SeGetCertInfoW(__in const std::wstring &file, __out std::vector<UNONE::CertInfoW> &infos, __in bool revoked_check)
{
	auto ret = OpSignatureInfoW(file, infos, revoked_check, false);
	return ret;
}


}