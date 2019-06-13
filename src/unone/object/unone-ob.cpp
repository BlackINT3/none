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
#include <tchar.h>
#include <common/unone-common.h>
#include <native/unone-native.h>
#include <internal/unone-internal.h>
#include <string/unone-str.h>
#include "unone-ob.h"

namespace {

}

namespace UNONE {
/*++
Description:
	parse symbolic link name
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008} => \Device\HarddiskVolume3
Arguments:
	symlnk - symbolic lnk name
	target - parsed name
Return:
	bool
--*/
bool ObParseSymbolicLinkA(__in const std::string& symlnk, __out std::string& target)
{
	std::wstring target_w;
	if (ObParseSymbolicLinkW(StrToW(symlnk), target_w)) {
		target = StrToA(target_w);
		return true;
	}
	return false;
}

/*++
Description:
	parse symbolic link name
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008} => \Device\HarddiskVolume3
Arguments:
	symlnk - symbolic lnk name
	target - parsed name
Return:
	bool
--*/
bool ObParseSymbolicLinkW(__in const std::wstring& symlnk, __out std::wstring& target)
{
	bool result = false;
	do {
		WCHAR* buff;
		ULONG retlen;
		HANDLE symlnk_obj;
		OBJECT_ATTRIBUTES oa;
		UNICODE_STRING ustr, name_str;
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		__RtlInitUnicodeString pRtlInitUnicodeString = (__RtlInitUnicodeString)GetProcAddress(ntdll,"RtlInitUnicodeString");
		if (pRtlInitUnicodeString == NULL)
			break;
		__NtOpenSymbolicLinkObject pNtOpenSymbolicLinkObject = (__NtOpenSymbolicLinkObject)GetProcAddress(ntdll,"NtOpenSymbolicLinkObject");
		if (pNtOpenSymbolicLinkObject == NULL)
			break;
		__NtQuerySymbolicLinkObject pNtQuerySymbolicLinkObject = (__NtQuerySymbolicLinkObject) GetProcAddress(ntdll,"NtQuerySymbolicLinkObject");
		if (pNtQuerySymbolicLinkObject == NULL)
			break;
		__NtClose pNtClose = (__NtClose)GetProcAddress(ntdll,"NtClose");
		if (!pNtClose)
			break;
		pRtlInitUnicodeString(&ustr, symlnk.c_str());
		InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
		NTSTATUS status = pNtOpenSymbolicLinkObject(&symlnk_obj, SYMBOLIC_LINK_QUERY, &oa);
		if (!NT_SUCCESS(status))
			break;
		buff = new(std::nothrow) WCHAR[512];
		if (!buff)
			break;
		RtlZeroMemory(buff, 512*2);
		name_str.Buffer = buff;
		name_str.Length = 0;
		name_str.MaximumLength = 512*2;
		status = pNtQuerySymbolicLinkObject(symlnk_obj, &name_str, &retlen);
		if (!NT_SUCCESS(status)) {
			delete[] buff;
			if (status != STATUS_BUFFER_TOO_SMALL)
				break;
			buff = new(std::nothrow) WCHAR[retlen/2];
			if (!buff)
				break;
			RtlZeroMemory(buff, retlen);
			name_str.Buffer = buff;
			name_str.Length = 0;
			name_str.MaximumLength = (USHORT)retlen;
			status = pNtQuerySymbolicLinkObject(symlnk_obj, &name_str, &retlen);
			if (!NT_SUCCESS(status))
				break;
		}
		target.assign(name_str.Buffer, name_str.Length/2);
		result = true;
		delete[] buff;
	} while (0);
	return result;
}

/*++
Description:
	parse symbolic link / nt path to dos path
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008}\Windows => C:\Windows
	\Device\HarddiskVolume3\Windows => C:\Windows
Arguments:
	ori_path - symbolic link path / nt path
	dos_path - dos path
Return:
	bool
--*/
bool ObParseToDosPathA(__in std::string ori_path, __out std::string& dos_path)
{
	std::wstring wstr;
	if (ObParseToDosPathW(StrToW(ori_path), wstr)) {
		dos_path = StrToA(wstr);
		return true;
	}
	return false;
}

/*++
Description:
	parse symbolic link / NT path to DOS path
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008}\Windows => C:\Windows
	\Device\HarddiskVolume3\Windows => C:\Windows
Arguments:
	ori_path - symbolic link path / NT path
	dos_path - dos path
Return:
	bool
--*/
bool ObParseToDosPathW(__in std::wstring ori_path, __out std::wstring& dos_path)
{
	bool result = false;

	//symbolic name
	std::wstring dospath, wstr, symlnk;
	WCHAR* path = (WCHAR*)ori_path.c_str();
	if (wcsncmp(path,L"\\??\\",sizeof(L"\\??\\")/2-1) == 0) {
		symlnk = path;
		symlnk = StrTruncateW(symlnk,L"\\??\\",L"\\");
		symlnk = L"\\??\\" + symlnk;
		if (ObParseSymbolicLinkW(symlnk,wstr)) {
			WCHAR* subpath = path + symlnk.size();
			ori_path = wstr + subpath;
		}
	}

	//parse nt path
	const DWORD driveslen = sizeof(DWORD)*('Z'-'A'+2);
	WCHAR drives[driveslen] = {0};
	DWORD size = GetLogicalDriveStringsW(driveslen, drives);
	if (size < driveslen) {
		DWORD i = 0;
		while (i < size) {
			WCHAR target[MAX_PATH*2] = {0};
			WCHAR volume[3] = L" :";
			volume[0] = drives[i];
			i += sizeof(DWORD);
			if (QueryDosDeviceW(volume, target, MAX_PATH*2-1) == 0)
				continue;
			int targetlen = (int)wcslen(target);
			if (_wcsnicmp(ori_path.c_str(), target, targetlen) == 0) {
				dos_path = volume + ori_path.substr(targetlen);
				result = true;
				break;
			}
		}
	}
	return result;
}

/*++
Description:
	parse symbolic link / DOS path to NT path
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008}\Windows => \Device\HarddiskVolume3\Windows
	C:\Windows => \Device\HarddiskVolume3\Windows
Arguments:
	ori_path - symbolic link path / DOS path
	nt_path - NT path
Return:
	bool
--*/
bool ObParseToNtPathA(__in std::string ori_path, __out std::string& nt_path)
{
	std::wstring wstr;
	if (ObParseToNtPathW(StrToW(ori_path), wstr)) {
		nt_path = StrToA(wstr);
		return true;
	}
	return false;
}

/*++
Description:
	parse symbolic link / DOS path to NT path
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008}\Windows => \Device\HarddiskVolume3\Windows
	C:\Windows => \Device\HarddiskVolume3\Windows
Arguments:
	ori_path - symbolic link path / DOS path
	nt_path - NT path
Return:
	bool
--*/
bool ObParseToNtPathW(__in std::wstring ori_path, __out std::wstring& nt_path)
{
	//symbolic name
	std::wstring wstr, symlnk;
	WCHAR* path = (WCHAR*)ori_path.c_str();
	if (wcsncmp(path,L"\\??\\",sizeof(L"\\??\\")/2-1) == 0) {
		symlnk = path;
		symlnk = StrTruncateW(symlnk,L"\\??\\",L"\\");
		symlnk = L"\\??\\" + symlnk;
		if (ObParseSymbolicLinkW(symlnk,wstr)) {
			WCHAR* subpath = path + symlnk.size();
			nt_path = wstr + subpath;
			return true;
		}
		return false;
	}

	//dos path
	if (ori_path.size()<2 || ori_path[1]!=L':') {
		UNONE_ERROR(L"DosPath:%s illegal", ori_path.c_str());
		return false;
	}
	std::wstring volume = ori_path.substr(0,2);
	std::wstring rel = ori_path.substr(2);
	WCHAR target[MAX_PATH*2] = {0};
	if (QueryDosDeviceW(volume.c_str(), target, MAX_PATH*2-1) == 0) {
		UNONE_ERROR(L"QueryDosDeviceW %s err:%d", volume.c_str(), GetLastError());
		return false;
	}
	nt_path = target + rel;
	return true;
}

}