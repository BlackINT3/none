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

namespace UNONE {

#ifdef _UNICODE
#define ObParseSymbolicLink ObParseSymbolicLinkW
#define ObParseToDosPath ObParseToDosPathW
#define ObParseToNtPath ObParseToNtPathW
#else
#define ObParseSymbolicLink ObParseSymbolicLinkA
#define ObParseToDosPath ObParseToDosPathA
#define ObParseToNtPath ObParseToNtPathA
#endif // _UNICODE

UNONE_API bool ObParseSymbolicLinkA(__in const std::string& symlnk, __out std::string& target);
UNONE_API bool ObParseSymbolicLinkW(__in const std::wstring& symlnk, __out std::wstring& target);
UNONE_API bool ObParseToDosPathA(__in std::string ori_path, __out std::string& dos_path);
UNONE_API bool ObParseToDosPathW(__in std::wstring ori_path, __out std::wstring& dos_path);
UNONE_API bool ObParseToNtPathA(__in std::string ori_path, __out std::string& nt_path);
UNONE_API bool ObParseToNtPathW(__in std::wstring ori_path, __out std::wstring& nt_path);
UNONE_API bool ObLoadDriverA(__in const std::string &file_path, __in std::string srv_name = "");
UNONE_API bool ObLoadDriverW(__in const std::wstring &file_path, __in std::wstring srv_name = L"");
UNONE_API bool ObUnloadDriverA(__in const std::string &srv_name);
UNONE_API bool ObUnloadDriverW(__in const std::wstring &srv_name);
UNONE_API bool ObGetDriverList(__out std::vector<LPVOID> &drivers);
UNONE_API std::string ObGetDriverNameA(__in LPVOID driver);
UNONE_API std::wstring ObGetDriverNameW(__in LPVOID driver);
UNONE_API std::string ObGetDriverPathA(__in LPVOID driver);
UNONE_API std::wstring ObGetDriverPathW(__in LPVOID driver);
UNONE_API std::string ObGetNtKernelFilePath();
} // namespace UNONE