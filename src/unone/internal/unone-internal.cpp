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
#include <stack>
#include "unone-internal.h"
#include <common/unone-common.h>
#include <string/unone-str.h>

namespace UNONE {
typedef std::stack<LogCallback> LoggerType;
DWORD global_idx = TLS_OUT_OF_INDEXES;

bool InterCreateTlsValue(LPVOID val, DWORD &tlsid)
{
	DWORD idx = tlsid;
	if (idx == TLS_OUT_OF_INDEXES) {
		idx = TlsAlloc();
	}
	if (idx == TLS_OUT_OF_INDEXES) return false;
	tlsid = idx;
	bool ret = TlsSetValue(idx, val);
	if (!ret) {
		TlsFree(idx);
		return false;
	}
	return true;
}

bool InterGetTlsValue(DWORD tlsid, LPVOID &val)
{
	if (tlsid == TLS_OUT_OF_INDEXES) return false;
	val = TlsGetValue(tlsid);
	return true;
}

bool InterDeleteTlsValue(DWORD &tlsid)
{
	if (tlsid == TLS_OUT_OF_INDEXES) return false;
	TlsSetValue(tlsid, nullptr);
	TlsFree(tlsid);
	tlsid = TLS_OUT_OF_INDEXES;
	return true;
}

bool InterRegisterLogger(__in LogCallback routine)
{
	LoggerType *loggers = nullptr;
	bool initial = false;
	if (global_idx != TLS_OUT_OF_INDEXES) {
		loggers = (LoggerType*)TlsGetValue(global_idx);
	}
	if (!loggers) {
		DWORD idx = global_idx;
		if (idx == TLS_OUT_OF_INDEXES) {
			idx = TlsAlloc();
			if (idx == TLS_OUT_OF_INDEXES) return false;
			global_idx = idx;
		}
		loggers = new(std::nothrow) std::stack<LogCallback>;
		if (!loggers) {
			return false;
		}
		TlsSetValue(idx, loggers);
	}
	loggers->push(routine);
	return true;
}

bool InterUnregisterLogger()
{
	if (global_idx == TLS_OUT_OF_INDEXES) return false;
	LoggerType *loggers = nullptr;
	loggers = (LoggerType*)TlsGetValue(global_idx);
	if (!loggers) return false;
	loggers->pop();
	if (loggers->size() == 0) {
		delete loggers;
		loggers = nullptr;
		TlsSetValue(global_idx, nullptr);
	}
	return true;
}

bool InterCurrentLogger(__out LogCallback &routine)
{
	if (global_idx == TLS_OUT_OF_INDEXES) return false;
	LoggerType *loggers = nullptr;
	loggers = (LoggerType*)TlsGetValue(global_idx);
	if (!loggers) return false;
	routine = loggers->top();
	return true;
}

void InertLoggerOutput(__in LogOuputLevel lev, __in const char* func, __in const wchar_t* format, ...)
{
	LogCallback routine;
	if (!InterCurrentLogger(routine)) return;

	std::wstring levelstr;
	struct { int lev; wchar_t* levstr; } levels[] = {
		{ LevelInfo , (wchar_t*)L"[INFO]" },
		{ LevelWarn , (wchar_t*)L"[WARN]" },
		{ LevelErr , (wchar_t*)L"[ERR]" },
		{ LevelDbg , (wchar_t*)L"[DBG]" },
		{ LevelFatal , (wchar_t*)L"[FATAL]" },
	};
	for (int i = 0; i < _countof(levels); i++) {
		if (levels[i].lev == lev) {
			levelstr = levels[i].levstr;
			break;
		}
	}
	std::wstring &&prefix = StrFormatW(L"[%s] %s %s", StrToW(func).c_str(), levelstr.c_str(), format);
	va_list lst;
	va_start(lst, format);
	std::wstring &&wstr = UNONE::StrFormatVaListW(prefix.c_str(), lst);
	va_end(lst);

	routine(wstr);
}

void InertLoggerOutput(__in LogOuputLevel lev, __in const char* func, __in const char* format, ...)
{
	LogCallback routine;
	if (!InterCurrentLogger(routine)) return;

	va_list lst;
	va_start(lst, format);
	std::wstring &&wstr = UNONE::StrToW(UNONE::StrFormatVaListA(format, lst));
	InertLoggerOutput(lev, func, L"%s", wstr.c_str());
	va_end(lst);
}

};

