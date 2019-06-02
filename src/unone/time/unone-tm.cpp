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
#ifndef _CRT_RAND_S
#define _CRT_RAND_S
#endif
#include "../common/unone-common.h"
#include "../internal/unone-internal.h"
#include "../string/unone-str.h"
#include "unone-tm.h"
#include <tchar.h>

namespace UNONE {

/*++
Description:
	windows system time to unix timestamp
Arguments:
	systm - system time
	unixtm - unix timestamp
Return:
	bool
--*/
bool TmSystemToUnixTime(__in SYSTEMTIME& systm, __out time_t& unixtm)
{
	LARGE_INTEGER unix_utc = {0};
	LARGE_INTEGER filetm = {0};
	unix_utc.QuadPart = 116444736000000000I64;
	if (!SystemTimeToFileTime(&systm, (FILETIME*)&filetm))
		return false;
	unixtm = (time_t)((filetm.QuadPart - unix_utc.QuadPart) / 10000000);
	return true;
}

/*++
Description:
	unix timestamp to windows system time
Arguments:
	unixtm - unix timestamp
	systm - system time
Return:
	bool
--*/
bool TmUnixToSystemTime(__in time_t unixtm, __out SYSTEMTIME& systm)
{
	LARGE_INTEGER unix_utc = {0};
	LARGE_INTEGER filetm = {0};
	unix_utc.QuadPart = 116444736000000000I64;
	filetm.QuadPart = (unsigned __int64)unixtm * 10000000 + unix_utc.QuadPart;
	FileTimeToSystemTime((FILETIME*)&filetm, &systm);
	TmConvertZoneTime(systm, NULL);
	return true;
}

/*++
Description:
	system time convert specific zone time
Arguments:
	systm - system time
	zone - time zone
Return:
	bool
--*/
bool TmConvertZoneTime(__inout SYSTEMTIME& systm, __in LPTIME_ZONE_INFORMATION zone)
{
	return SystemTimeToTzSpecificLocalTime(zone, &systm, &systm) ? true : false;
}

/*++
Description:
	millisecond(1601.01.01) to unix time
Arguments:
	ms - millisecond
Return:
	unix time
--*/
time_t TmMsToUnixTime(__in LONGLONG ms)
{
	time_t unix;
	TmSystemToUnixTime(TmMsToSystemTime(ms), unix);
	return unix;
}

/*++
Description:
	millisecond(1601.01.01) to file time
Arguments:
	ms - millisecond
Return:
	file time
--*/
FILETIME TmMsToFileTime(__in LONGLONG ms)
{
	FILETIME ft;
	LARGE_INTEGER li;
	li.QuadPart = ms * 10000;
	ft.dwHighDateTime = li.HighPart;
	ft.dwLowDateTime = li.LowPart;
	return ft;
}

/*++
Description:
	millisecond(1601.01.01) to system time
Arguments:
	ms - millisecond
Return:
	system time
--*/
SYSTEMTIME TmMsToSystemTime(__in LONGLONG ms)
{
	SYSTEMTIME systm;
	FILETIME ft = TmMsToFileTime(ms);
	FileTimeToSystemTime(&ft, &systm);
	return systm;
}

/*++
Description:
	unix time to millisecond(1601.01.01)
Arguments:
	ms - millisecond
Return:
	millisecond
--*/
LONGLONG TmUnixTimeToMs(__in const time_t& unix)
{
	SYSTEMTIME systm;
	TmUnixToSystemTime(unix, systm);
	return TmSystemTimeToMs(systm);
}

/*++
Description:
	file time to millisecond(1601.01.01)
Arguments:
	ms - millisecond
Return:
	millisecond
--*/
LONGLONG TmFileTimeToMs(__in const FILETIME& ft)
{
	LARGE_INTEGER li;
	li.HighPart = ft.dwHighDateTime;
	li.LowPart = ft.dwLowDateTime;
	return li.QuadPart / 10000;
}

/*++
Description:
	system time to millisecond(1601.01.01)
Arguments:
	ms - millisecond
Return:
	millisecond
--*/
LONGLONG TmSystemTimeToMs(__in const SYSTEMTIME& systm)
{
	FILETIME ft;
	SystemTimeToFileTime(&systm, &ft);
	return TmFileTimeToMs(ft);
}

/*++
Description:
	system time to millisecond(1601.01.01)
Arguments:
	ms - millisecond
	format - format string
Return:
	unix time formatted string
--*/
std::string TmFormatUnixTimeA(__in const time_t& unix, __in const std::string& format)
{
	return StrToA(TmFormatUnixTimeW(unix, StrToW(format)));
}

/*++
Description:
	system time to millisecond(1601.01.01)
Arguments:
	ms - millisecond
	format - format string
Return:
	unix time formatted string
--*/
std::wstring TmFormatUnixTimeW(__in const time_t& unix, __in const std::wstring& format)
{
	SYSTEMTIME systm;
	TmUnixToSystemTime(unix, systm);
	return TmFormatSystemTimeW(systm, format);
}

/*++
Description:
	format millisecond(1601.01.01) to string
Arguments:
	ms - millisecond
	format - format string
	zone - time zone
Return:
	formatted string
--*/
std::string TmFormatMsA(__in LONGLONG ms, __in const std::string& format, __in LPTIME_ZONE_INFORMATION zone)
{
	return StrToA(TmFormatMsW(ms, StrToW(format), zone));
}

/*++
Description:
	format millisecond(1601.01.01) to string
Arguments:
	ms - millisecond
	format - format string
	zone - time zone
Return:
	formatted string
--*/
std::wstring TmFormatMsW(__in LONGLONG ms, __in const std::wstring& format, __in LPTIME_ZONE_INFORMATION zone)
{
	SYSTEMTIME systm = TmMsToSystemTime(ms);
	TmConvertZoneTime(systm, zone);
	return TmFormatSystemTimeW(systm, format);
}

/*++
Description:
	format file time to string
Arguments:
	ft - file time
	format - format string
Return:
	formatted string
--*/
std::string TmFormatFileTimeA(__in const FILETIME& ft, __in const std::string& format)
{
	return StrToA(TmFormatFileTimeW(ft, StrToW(format)));
}

/*++
Description:
	format file time to string
Arguments:
	ft - file time
	format - format string
Return:
	formatted string
--*/
std::wstring TmFormatFileTimeW(__in const FILETIME& ft, __in const std::wstring& format)
{
	SYSTEMTIME systm;
	FileTimeToSystemTime((FILETIME*)&ft, &systm);
	return TmFormatSystemTimeW(systm, format);
}

/*++
Description:
	format system time to string
Arguments:
	systm - system time
	format - format string
Return:
	formatted string
--*/
std::string TmFormatSystemTimeA(__in const SYSTEMTIME& systm, __in const std::string& format)
{
	return StrToA(TmFormatSystemTimeW(systm, StrToW(format)));
}

/*++
Description:
	format system time to string
Arguments:
	systm - system time
	format - format string
Return:
	formatted string
--*/
std::wstring TmFormatSystemTimeW(__in const SYSTEMTIME& systm, __in const std::wstring& format)
{
	std::wstring wstr = format;
	StrReplaceW(wstr, L"y", StrFormatW(L"%d", systm.wYear));
	StrReplaceW(wstr, L"Y", StrFormatW(L"%04d", systm.wYear));
	StrReplaceW(wstr, L"m", StrFormatW(L"%d", systm.wMonth));
	StrReplaceW(wstr, L"M", StrFormatW(L"%02d", systm.wMonth));
	StrReplaceW(wstr, L"d", StrFormatW(L"%d", systm.wDay));
	StrReplaceW(wstr, L"D", StrFormatW(L"%02d", systm.wDay));
	StrReplaceW(wstr, L"h", StrFormatW(L"%d", systm.wHour));
	StrReplaceW(wstr, L"H", StrFormatW(L"%02d", systm.wHour));
	StrReplaceW(wstr, L"w", StrFormatW(L"%d", systm.wMinute));
	StrReplaceW(wstr, L"W", StrFormatW(L"%02d", systm.wMinute));
	StrReplaceW(wstr, L"s", StrFormatW(L"%d", systm.wSecond));
	StrReplaceW(wstr, L"S", StrFormatW(L"%02d", systm.wSecond));
	StrReplaceW(wstr, L"x", StrFormatW(L"%d", systm.wMilliseconds));
	StrReplaceW(wstr, L"X", StrFormatW(L"%03d", systm.wMilliseconds));
	return wstr;
}

} // namespace UNONE