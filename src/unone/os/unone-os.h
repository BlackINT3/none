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
#define OsNetBiosName OsNetBiosNameW
#define OsHostName OsHostNameW
#define OsSysDir32 OsSysDir32W
#define OsSystem32Dir OsSystem32DirW
#define OsSyswow64Dir OsSyswow64DirW
#define OsDosErrorMsg OsDosErrorMsgW
#else
#define OsNetBiosName OsNetBiosNameA
#define OsHostName OsHostNameA
#define OsSysDir32 OsSysDir32A
#define OsSystem32Dir OsSystem32DirA
#define OsSyswow64Dir OsSyswow64DirA
#define OsDosErrorMsg OsDosErrorMsgA
#endif // _UNICODE

UNONE_API bool OsIs64();
UNONE_API bool OsIsVistaUpper();
UNONE_API DWORD OsMajorVer();
UNONE_API DWORD OsMinorVer();
UNONE_API DWORD OsBuildNumber();
UNONE_API DWORD OsReleaseNumber();
UNONE_API std::string OsNetBiosNameA();
UNONE_API std::wstring OsNetBiosNameW();
UNONE_API std::string OsHostNameA();
UNONE_API std::wstring OsHostNameW();
UNONE_API std::string OsUserNameA();
UNONE_API std::wstring OsUserNameW();
UNONE_API std::string OsSessionUserNameA(__in DWORD id);
UNONE_API std::wstring OsSessionUserNameW(__in DWORD id);
UNONE_API std::string OsWinDirA();
UNONE_API std::wstring OsWinDirW();
UNONE_API std::string OsSysDir32A();
UNONE_API std::wstring OsSysDir32W();
UNONE_API std::string OsSystem32DirA();
UNONE_API std::wstring OsSystem32DirW();
UNONE_API std::string OsSyswow64DirA();
UNONE_API std::wstring OsSyswow64DirW();
UNONE_API uint64_t OsTickCount();
UNONE_API LONGLONG OsStartupTime();
UNONE_API std::string OsStartupTimeStrA(const std::string& format = "Y-M-D H:W:S");
UNONE_API std::wstring OsStartupTimeStrW(const std::wstring& format = L"Y-M-D H:W:S");
UNONE_API std::string OsEnvironmentA(const std::string &env);
UNONE_API std::wstring OsEnvironmentW(const std::wstring &env);
UNONE_API DWORD OsNtToDosError(__in LONG status);
UNONE_API std::string OsDosErrorMsgA(__in DWORD err);
UNONE_API std::wstring OsDosErrorMsgW(__in DWORD err);
UNONE_API bool OsFastReboot();
UNONE_API bool OsFastPoweroff();
} // namespace UNONE