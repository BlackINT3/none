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
#include <functional>
#include <string>

#ifdef UNONE_DLL
#define UNONE_API __declspec(dllexport)
#else
#define UNONE_API
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAKELONGLONG
#define MAKELONGLONG(a, b) ((LONGLONG(DWORD(a) & 0xFFFFFFFF) << 32 ) | LONGLONG(DWORD(b) & 0xFFFFFFFF))
#endif
#ifndef MAKEULONGLONG
#define MAKEULONGLONG(a, b) ((ULONGLONG(DWORD(a) & 0xFFFFFFFF) << 32 ) | ULONGLONG(DWORD(b) & 0xFFFFFFFF))
#endif

//1 => '1' / A => 'A'
#ifndef HEX_TO_CHAR
#define HEX_TO_CHAR(x)	((unsigned char)(x) > 9 ? (unsigned char)(x) -10 + 'a': (unsigned char)(x) + '0')
#endif
//'1' => 1 / 'A' => A
#ifndef CHAR_TO_HEX
#define CHAR_TO_HEX(x)	(isdigit((unsigned char)(x)) ? (unsigned char)(x)-'0' : (unsigned char)(toupper(x))-'a'+10)
#endif

#ifndef IN_RANGE
#define IN_RANGE(pos,begin,size) (((ULONGLONG)pos>=(ULONGLONG)begin) && ((ULONGLONG)pos<=((ULONGLONG)begin+size)))
#endif
#ifndef UP_ALIGN
#define UP_ALIGN(x,y)	((x+y-1)& ~(y-1))
#endif
#ifndef DOWN_ALIGN
#define DOWN_ALIGN(x,y) ((x)& ~(y-1))
#endif

namespace UNONE {

typedef std::function<void(const std::wstring &log)> LogCallback;
enum LogOuputLevel {
	LevelInfo,
	LevelWarn,
	LevelErr,
	LevelDbg,
	LevelFatal,
};

bool InterRegisterLogger(__in LogCallback routine);
bool InterUnregisterLogger();
bool InterCurrentLogger(__out LogCallback &routine);
void InertLoggerOutput(__in LogOuputLevel lev, __in const char* func, __in const char* format, ...);
void InertLoggerOutput(__in LogOuputLevel lev, __in const char* func, __in const wchar_t* format, ...);

} // namespace UNONE

#define UNONE_INFO(format, ...)  \
	UNONE::InertLoggerOutput(UNONE::LevelInfo, __FUNCTION__, (format), __VA_ARGS__)
#define UNONE_WARN(format, ...)  \
	UNONE::InertLoggerOutput(UNONE::LevelWarn, __FUNCTION__, (format), __VA_ARGS__)
#define UNONE_ERROR(format, ...)  \
	UNONE::InertLoggerOutput(UNONE::LevelErr, __FUNCTION__, (format), __VA_ARGS__)
#define UNONE_DEBUG(format, ...)  \
	UNONE::InertLoggerOutput(UNONE::LevelDbg, __FUNCTION__, (format), __VA_ARGS__)
#define UNONE_FATAL(format, ...)  \
	UNONE::InertLoggerOutput(UNONE::LevelFatal, __FUNCTION__, (format), __VA_ARGS__)