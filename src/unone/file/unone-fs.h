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
#pragma once
#include <Windows.h>
#include <string>
#include <functional>

#pragma comment(lib, "Version.lib")

namespace UNONE {

#ifdef _UNICODE
#define FsGetFileSize FsGetFileSizeW
#define FsReadFileData FsReadFileDataW
#define FsWriteFileData FsWriteFileDataW
#define FsPathToName FsPathToNameW
#define FsPathToDir FsPathToDirW
#define FsPathCompose FsPathComposeW
#define FsPathStandard FsPathStandardW
#define FsCreateDir FsCreateDirW
#define FsIsExisted FsIsExistedW
#define FsIsDir FsIsDirW
#define FsIsFile FsIsFileW
#define FsGetFileInfo FsGetFileInfoW
#define FsCopy FsCopyW
#define FsCopyFile FsCopyFileW
#define FsCopyDirectory FsCopyDirectoryW
#else
#define FsGetFileSize FsGetFileSizeA
#define FsReadFileData FsReadFileDataA
#define FsWriteFileData FsWriteFileDataA
#define FsInsertFileData FsInsertFileDataA
#define FsPathToName FsPathToNameA
#define FsPathToDir FsPathToDirA
#define FsPathCompose FsPathComposeA
#define FsPathStandard FsPathStandardA
#define FsCreateDir FsCreateDirA
#define FsIsExisted FsIsExistedA
#define FsIsDir FsIsDirA
#define FsIsFile FsIsFileA
#define FsGetFileInfo FsGetFileInfoA
#define FsCopy FsCopyA
#define FsCopyFile FsCopyFileA
#define FsCopyDirectory FsCopyDirectoryA
#endif // _UNICODE

typedef std::function<bool(char* path, char* name, void* param)> FileCallbackA;
typedef std::function<bool(wchar_t* path, wchar_t* name, void* param)> FileCallbackW;

UNONE_API bool FsDisableRedirection(__out PVOID& old_value);
UNONE_API bool FsEnableRedirection(__in PVOID& old_value);
UNONE_API bool FsGetFileSizeA(__in const std::string& fpath, __out DWORD64& fsize);
UNONE_API bool FsGetFileSizeW(__in const std::wstring& fpath, __out DWORD64& fsize);
UNONE_API bool FsReadFileDataA(__in const std::string& fpath, __out std::string& fdata);
UNONE_API bool FsReadFileDataW(__in const std::wstring& fpath, __out std::string& fdata);
UNONE_API bool FsWriteFileDataA(__in const std::string& fpath, __in const std::string& fdata);
UNONE_API bool FsWriteFileDataW(__in const std::wstring& fpath, __in const std::string& fdata);
UNONE_API bool FsInsertFileDataA(__in const std::string& fpath, __in std::string fdata, __in size_t pos = -1);
UNONE_API bool FsInsertFileDataW(__in const std::wstring& fpath, __in std::string fdata, __in size_t pos = -1);

UNONE_API std::string FsPathToNameA(__in const std::string& fpath);
UNONE_API std::wstring FsPathToNameW(__in const std::wstring& fpath);
UNONE_API std::string FsPathToDirA(__in const std::string& fpath, __in int up_level = 1);
UNONE_API std::wstring FsPathToDirW(__in const std::wstring& fpath, __in int up_level = 1);
UNONE_API std::string FsPathComposeA(__in const std::string& fpath, __in const std::string& subpath);
UNONE_API std::wstring FsPathComposeW(__in const std::wstring& fpath, __in const std::wstring& subpath);
UNONE_API std::string FsPathStandardA(__in const std::string& fpath);
UNONE_API std::wstring FsPathStandardW(__in const std::wstring& fpath);

UNONE_API bool FsIsExistedA(const std::string& path);
UNONE_API bool FsIsExistedW(const std::wstring& path);
UNONE_API bool FsIsDirA(const std::string& path);
UNONE_API bool FsIsDirW(const std::wstring& path);
UNONE_API bool FsIsFileA(const std::string& path);
UNONE_API bool FsIsFileW(const std::wstring& path);

UNONE_API bool FsGetFileInfoA(__in const std::string& path, __in const char* type, __out std::string& info, __in const char* translation = NULL);
UNONE_API bool FsGetFileInfoW(__in const std::wstring& path, __in const wchar_t* type, __out std::wstring& info, __in const wchar_t* translation = NULL);
UNONE_API LONGLONG FsGetFileVersionA(__in const std::string& path, __out std::string& version);
UNONE_API LONGLONG FsGetFileVersionW(__in const std::wstring& path, __out std::wstring& version);
UNONE_API LONGLONG FsGetFileCreateTimeA(__in const std::string& path);
UNONE_API LONGLONG FsGetFileCreateTimeW(__in const std::wstring& path);
UNONE_API LONGLONG FsGetFileAccessTimeA(__in const std::string& path);
UNONE_API LONGLONG FsGetFileAccessTimeW(__in const std::wstring& path);
UNONE_API LONGLONG FsGetFileModifyTimeA(__in const std::string& path);
UNONE_API LONGLONG FsGetFileModifyTimeW(__in const std::wstring& path);
UNONE_API bool FsGetFileTimeA(__in const std::string& path, __inout LONGLONG* create_tm, __inout LONGLONG* access_tm, __inout LONGLONG* modify_tm);
UNONE_API bool FsGetFileTimeW(__in const std::wstring& path, __inout LONGLONG* create_tm, __inout LONGLONG* access_tm, __inout LONGLONG* modify_tm);

UNONE_API bool FsEnumDirectoryA(__in const std::string& dir, __inout FileCallbackA callback, __in void* param = nullptr);
UNONE_API bool FsEnumDirectoryW(__in const std::wstring& dir, __inout FileCallbackW callback, __in void* param = nullptr);
UNONE_API bool FsCreateDirA(const std::string& dir);
UNONE_API bool FsCreateDirW(const std::wstring& dir);
UNONE_API bool FsCopyA(const std::string &src, const std::string &dst);
UNONE_API bool FsCopyW(const std::wstring &src, const std::wstring &dst);
UNONE_API bool FsCopyFileA(const std::string &src, const std::string &dst);
UNONE_API bool FsCopyFileW(const std::wstring &src, const std::wstring &dst);
UNONE_API bool FsCopyDirectoryA(const std::string &src, const std::string &dst);
UNONE_API bool FsCopyDirectoryW(const std::wstring &src, const std::wstring &dst);
UNONE_API bool FsDeleteDirectoryA(__in const std::string& dir);
UNONE_API bool FsDeleteDirectoryW(__in const std::wstring& dir);
} // namespace UNONE