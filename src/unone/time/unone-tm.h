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
#define TmFormatUnixTime TmFormatUnixTimeW
#define TmFormatMs TmFormatMsW
#define TmFormatFileTime TmFormatFileTimeW
#define TmFormatSystemTime TmFormatSystemTimeW
#else
#define TmFormatUnixTime TmFormatUnixTimeA
#define TmFormatMs TmFormatMsA
#define TmFormatFileTime TmFormatFileTimeA
#define TmFormatSystemTime TmFormatSystemTimeA
#endif // _UNICODE

UNONE_API time_t TmSystemToUnixTime(__in SYSTEMTIME& systm);
UNONE_API SYSTEMTIME TmUnixToSystemTime(__in time_t unixtm);
UNONE_API SYSTEMTIME TmConvertZoneTime(__in SYSTEMTIME systm, __in LPTIME_ZONE_INFORMATION zone);
UNONE_API time_t TmMsToUnixTime(__in LONGLONG ms);
UNONE_API FILETIME TmMsToFileTime(__in LONGLONG ms);
UNONE_API SYSTEMTIME TmMsToSystemTime(__in LONGLONG ms);
UNONE_API SYSTEMTIME TmMsToFullTime(__in LONGLONG ms);
UNONE_API SYSTEMTIME TmFileTimeToSystem(__in const FILETIME& ft);
UNONE_API FILETIME TmSystemTimeToFile(__in const SYSTEMTIME& st);
UNONE_API LONGLONG TmUnixTimeToMs(__in const time_t& unix);
UNONE_API LONGLONG TmFileTimeToMs(__in const FILETIME& ft);
UNONE_API LONGLONG TmSystemTimeToMs(__in const SYSTEMTIME& systm);
UNONE_API std::string TmFormatUnixTimeA(__in const time_t& unix, __in const std::string& format);
UNONE_API std::wstring TmFormatUnixTimeW(__in const time_t& unix, __in const std::wstring& format);
UNONE_API std::string TmFormatMsA(__in LONGLONG ms, __in const std::string& format, __in LPTIME_ZONE_INFORMATION zone);
UNONE_API std::wstring TmFormatMsW(__in LONGLONG ms, __in const std::wstring& format, __in LPTIME_ZONE_INFORMATION zone);
UNONE_API std::string TmFormatFileTimeA(__in const FILETIME& ft, __in const std::string& format);
UNONE_API std::wstring TmFormatFileTimeW(__in const FILETIME& ft, __in const std::wstring& format);
UNONE_API std::string TmFormatSystemTimeA(__in const SYSTEMTIME& systm, __in const std::string& format);
UNONE_API std::wstring TmFormatSystemTimeW(__in const SYSTEMTIME& systm, __in const std::wstring& format);

} // namespace UNONE
