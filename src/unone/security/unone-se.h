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
#include <vector>

namespace UNONE {

#ifdef _UNICODE
#define SeEnablePrivilege SeEnablePrivilegeW
#define SeDisablePrivilege SeDisablePrivilegeW
#define SeVerifyCert SeVerifyCertW
#define SeVerifyMicrosoftCert SeVerifyMicrosoftCertW
#define SeGetCertInfo SeGetCertInfoW
#else
#define SeEnablePrivilege SeEnablePrivilegeA
#define SeDisablePrivilege SeDisablePrivilegeA
#define SeVerifyCert SeVerifyCertA
#define SeVerifyMicrosoftCert SeVerifyMicrosoftCertA
#define SeGetCertInfo SeGetCertInfoA
#endif // _UNICODE

struct CertInfoA {
	std::string sn;
	std::string owner;
};
struct CertInfoW {
	std::wstring sn;
	std::wstring owner;
};
UNONE_API bool SeEnablePrivilegeA(__in const char* priv_name, __in DWORD priv_number = 0);
UNONE_API bool SeEnablePrivilegeW(__in const wchar_t* priv_name, __in DWORD priv_number = 0);
UNONE_API bool SeDisablePrivilegeA(__in const char* priv_name, __in DWORD priv_number = 0);
UNONE_API bool SeDisablePrivilegeW(__in const wchar_t* priv_name, __in DWORD priv_number = 0);
UNONE_API bool SeEnableDebugPrivilege(__in bool natived = false);
UNONE_API bool SeDisableDebugPrivilege(__in bool natived = false);

UNONE_API bool SeVerifyCertA(__in const std::string &file, __in bool revoked_check);
UNONE_API bool SeVerifyCertW(__in const std::wstring &file, __in bool revoked_check = true);
UNONE_API bool SeVerifyMicrosoftCertA(__in const std::string &file, __in bool revoked_check);
UNONE_API bool SeVerifyMicrosoftCertW(__in const std::wstring &file, __in bool revoked_check = true);
UNONE_API bool SeGetCertInfoA(__in const std::string &file, __out std::vector<UNONE::CertInfoA> &infos, __in bool revoked_check);
UNONE_API bool SeGetCertInfoW(__in const std::wstring &file, __out std::vector<UNONE::CertInfoW> &infos, __in bool revoked_check = true);

} // namespace UNONE