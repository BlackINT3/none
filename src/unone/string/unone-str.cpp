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
#include <tchar.h>
#include <string>
#include <vector>
#include <algorithm>
#include <Windows.h>
#include "../common/unone-common.h"
#include "../internal/unone-internal.h"
#include "unone-str.h"

namespace {

//Wildcard string compare (globbing) by Jack Handy.
//from:https://www.codeproject.com/Articles/1088/Wildcard-string-compare-globbing
bool WildCmpA(const char *str, const char *wild, bool ci)
{
	const char *cp, *mp;
	while ((*str) && (*wild != '*')) {
		if (((*wild != *str) && (ci && tolower(*wild) != tolower(*str))) && (*wild != '?')) return false;
		wild++;
		str++;
	}
	while (*str) {
		if (*wild == '*') {
			if (!*++wild) return true;
			mp = wild;
			cp = str+1;
		} else if (((*wild == *str) || (ci && tolower(*wild) == tolower(*str))) || (*wild == '?')) {
			wild++;
			str++;
		}	else {
			wild = mp;
			str = cp++;
		}
	}
	while (*wild == '*') wild++;
	return !*wild;
}
bool WildCmpW(const wchar_t *str, const wchar_t *wild, bool ci)
{
	const wchar_t *cp, *mp;
	while ((*str) && (*wild != L'*')) {
		if (((*wild != *str) && (ci && tolower(*wild) != tolower(*str))) && (*wild != '?')) return false;
		wild++;
		str++;
	}
	while (*str) {
		if (*wild == L'*') {
			if (!*++wild) return true;
			mp = wild;
			cp = str+1;
		} else if (((*wild == *str) || (ci && tolower(*wild) == tolower(*str))) || (*wild == '?')) {
			wild++;
			str++;
		}	else {
			wild = mp;
			str = cp++;
		}
	}
	while (*wild == L'*') wild++;
	return !*wild;
}
}

namespace UNONE {

/*++
Description:
	string to upper
Arguments:
	str - origin string
Return:
	void
--*/
void StrUpperA(__inout std::string& str)
{
	try {
		for (size_t i = 0; i < str.size(); i++) {
			str[i] = toupper(str[i]);
		}
	} catch (...) {
	}
}

/*++
Description:
	string to lower
Arguments:
	str - origin string
Return:
	void
--*/
void StrLowerA(__inout std::string& str)
{
	try {
		for (size_t i = 0; i < str.size(); i++) {
			str[i] = tolower(str[i]);
		}
	} catch (...) {
	}
}

/*++
Description:
	string to upper
Arguments:
	wstr - origin wstring
Return:
	void
--*/
void StrUpperW(__inout std::wstring& wstr)
{
	try {
		for (size_t i = 0; i < wstr.size(); i++) {
			wstr[i] = toupper(wstr[i]);
		}
	} catch (...) {
	}
}

/*++
Description:
	string to lower
Arguments:
	wstr - origin wstring
Return:
	void
--*/
void StrLowerW(__inout std::wstring& wstr)
{
	try {
		for (size_t i = 0; i < wstr.size(); i++) {
			wstr[i] = tolower(wstr[i]);
		}
	} catch (...) {
	}
}

/*++
Description:
	string to upper
Arguments:
	str - origin string
Return:
	result string
--*/
std::string StrToUpperA(__in const std::string& str)
{
	try {
		std::string tmp(str);
		for (size_t i = 0; i < tmp.size(); i++) {
			tmp[i] = toupper(tmp[i]);
		}
		return std::move(tmp);
	} catch (...) {
		return "";
	}
}

/*++
Description:
	string to lower
Arguments:
	str - origin string
Return:
	result string
--*/
std::string StrToLowerA(__in const std::string& str)
{
	try {
		std::string tmp(str);
		for (size_t i = 0; i < tmp.size(); i++) {
			tmp[i] = tolower(tmp[i]);
		}
		return std::move(tmp);
	} catch (...) {
		return "";
	}
}

/*++
Description:
	string to upper
Arguments:
	wstr - origin wstring
Return:
	void
--*/
std::wstring StrToUpperW(__in const std::wstring& wstr)
{
	try {
		std::wstring tmp(wstr);
		for (size_t i = 0; i < tmp.size(); i++) {
			tmp[i] = toupper(tmp[i]);
		}
		return std::move(tmp);
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	string to lower
Arguments:
	wstr - origin wstring
Return:
	void
--*/
std::wstring StrToLowerW(__in const std::wstring& wstr)
{
	try {
		std::wstring tmp(wstr);
		for (size_t i = 0; i < tmp.size(); i++) {
			tmp[i] = tolower(tmp[i]);
		}
		return std::move(tmp);
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	string to hex
Arguments:
	str - hex string
Return:
	hex
--*/
unsigned int StrToHexA(__in const std::string& str)
{
	return (unsigned int)strtoul(str.c_str(), NULL, 16);
}

/*++
Description:
	wide string to hex
Arguments:
	wstr - hex wide string
Return:
	hex
--*/
unsigned int StrToHexW(__in const std::wstring& wstr)
{
	return (unsigned int)wcstoul(wstr.c_str(), NULL, 16);
}

/*++
Description:
	string to hex 64
Arguments:
	str - hex string
Return:
	hex 64
--*/
uint64_t StrToHex64A(__in const std::string& str)
{
	return (uint64_t)_strtoui64(str.c_str(), NULL, 16);
}

/*++
Description:
	wide string to hex 64
Arguments:
	wstr - hex wide string
Return:
	hex 64
--*/
uint64_t StrToHex64W(__in const std::wstring& wstr)
{
	return (uint64_t)_wcstoui64(wstr.c_str(), NULL, 16);
}

/*++
Description:
	string to decimal integer
Arguments:
	str - decimal integer string
Return:
	integer
--*/
int StrToIntegerA(__in const std::string& str)
{
	return (int)strtoul(str.c_str(), NULL, 10);
}

/*++
Description:
	wide string to decimal integer
Arguments:
	wstr - decimal integer wide string
Return:
	integer
--*/
int StrToIntegerW(__in const std::wstring& wstr)
{
	return (int)wcstoul(wstr.c_str(), NULL, 10);
}

/*++
Description:
	string to decimal integer 64
Arguments:
	str - decimal integer string
Return:
	decimal integer 64
--*/
int64_t StrToInteger64A(__in const std::string& str)
{
	return (int64_t)_strtoui64(str.c_str(), NULL, 10);
}

/*++
Description:
	wide string to decimal integer 64
Arguments:
	wstr - decimal integer wide string
Return:
	decimal 64
--*/
int64_t StrToInteger64W(__in const std::wstring& wstr)
{
	return (int64_t)_wcstoui64(wstr.c_str(), NULL, 10);
}

/*++
Description:
	string to octal
Arguments:
	str - integer string
Return:
	octal
--*/
int StrToOctalA(__in const std::string& str)
{
	return (int)strtoul(str.c_str(), NULL, 8);
}

/*++
Description:
	wide string to octal
Arguments:
	wstr - integer wide string
Return:
	octal
--*/
int StrToOctalW(__in const std::wstring& wstr)
{
	return (int)wcstoul(wstr.c_str(), NULL, 8);
}

/*++
Description:
	string to octal 64
Arguments:
	str - octal string
Return:
	octal 64
--*/
int64_t StrToOctal64A(__in const std::string& str)
{
	return (int64_t)_strtoui64(str.c_str(), NULL, 8);
}

/*++
Description:
	wide string to integer 64
Arguments:
	wstr - octal wide string
Return:
	octal 64
--*/
int64_t StrToOctal64W(__in const std::wstring& wstr)
{
	return (int64_t)_wcstoui64(wstr.c_str(), NULL, 8);
}


/*++
Description:
	string to binary
Arguments:
	str - binary string
Return:
	octal
--*/
int StrToBinaryA(__in const std::string& str)
{
	return (int)strtoul(str.c_str(), NULL, 2);
}

/*++
Description:
	wide string to binary
Arguments:
	wstr - binary wide string
Return:
	binary
--*/
int StrToBinaryW(__in const std::wstring& wstr)
{
	return (int)wcstoul(wstr.c_str(), NULL, 2);
}

/*++
Description:
	string to binary 64
Arguments:
	str - binary string
Return:
	binary 64
--*/
int64_t StrToBinary64A(__in const std::string& str)
{
	return (int64_t)_strtoui64(str.c_str(), NULL, 2);
}

/*++
Description:
	wide string to binary 64
Arguments:
	wstr - binary wide string
Return:
	binary 64
--*/
int64_t StrToBinary64W(__in const std::wstring& wstr)
{
	return (int64_t)_wcstoui64(wstr.c_str(), NULL, 2);
}

/*++
Description:
	UNICODE_STRING to wide string
Arguments:
	ustr - UNICODE_STRING
Return:
	wide string
--*/
std::wstring StrUstrToWide(__in void* ustr)
{
	typedef struct _UNICODE_STRING_X {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING_X;
	try {
		std::wstring wstr;
		if (ustr != nullptr) {
			wstr.assign(((UNICODE_STRING_X*)ustr)->Buffer, ((UNICODE_STRING_X*)ustr)->Length/2);
		}
		return wstr;
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	ANSI_STRING to string
Arguments:
	astr - ANSI_STRING
Return:
	string
--*/
std::string StrAstrToStr(__in void* astr)
{
	typedef struct _ANSI_STRING_X {
		USHORT Length;
		USHORT MaximumLength;
		PCHAR Buffer;
	} ANSI_STRING_X;
	try {
		std::string str;
		if (astr != nullptr) {
			str.assign(((ANSI_STRING_X*)astr)->Buffer, ((ANSI_STRING_X*)astr)->Length);
		}
		return str;
	} catch (...) {
		return "";
	}
}

/*++
Description:
	binary stream to hex string
	eg:
	"\xAB\xCD\xEF" => "ABCDEF"
Arguments:
	stream - binary stream
Return:
	hex string
--*/
std::string StrStreamToHexStrA(__in const std::string& stream)
{
	try {
		std::string hexstr;
		for (size_t i = 0; i < stream.size(); i++) {
			unsigned char ch = stream[i];
			hexstr.push_back(HEX_TO_CHAR(ch >> 4));
			hexstr.push_back(HEX_TO_CHAR(ch % 16));
		}
		return hexstr;
	} catch (...) {
		return "";
	}
}

/*++
Description:
	binary stream to hex string
	eg:
	L"\xAB\xCD\xEF" => "AB00CD00EF00", little endian
Arguments:
	stream - binary stream
Return:
	hex string
--*/
std::string StrStreamToHexStrW(__in const std::wstring& stream)
{
	std::string stream_s((char*)stream.c_str(), stream.size() * sizeof(wchar_t));
	return StrStreamToHexStrA(stream_s);
}

/*++
Description:
	hex string to binary stream
	eg:
	"ABCDEF" => "\xAB\xCD\xEF"
Arguments:
	str - hex string
Return:
	binary stream
--*/
std::string StrHexStrToStreamA(__in const std::string& hexstr)
{
	try {
		std::string stream;
		bool odd = false;
		unsigned char last = 0;
		size_t size = hexstr.size();

		//if hexstr length is odd£¬the last char would be handle differently. 
		if (size%2 != 0) {
			last = CHAR_TO_HEX(hexstr[size-1]) % 16;
			size--;
			odd = true;
		}
		for (size_t i = 0; i < size; i+=2) {
			unsigned char ch = 0;
			ch = CHAR_TO_HEX(hexstr[i]) << 4;
			ch |= CHAR_TO_HEX(hexstr[i+1]) % 16;
			stream.push_back(ch);
		}
		if (odd) {
			stream.push_back(last);
		}
		return stream;
	} catch (...) {
		return "";
	}
}

/*++
Description:
	hex string to binary stream
	eg:
	"AB00CD00EF00" => L"\xAB\xCD\xEF", little endian
Arguments:
	str - hex string
Return:
	binary stream
--*/
std::wstring StrHexStrToStreamW(__in const std::string& hexstr)
{
	std::string&& str = StrHexStrToStreamA(hexstr);
	return std::wstring((wchar_t*)str.c_str(), str.size()/sizeof(wchar_t));
}

/*++
Description:
	wide to string
	eg:
	L"Hello UNONE" => "Hello UNONE"
Arguments:
	wstr - wide string
Return:
	string
--*/
std::string StrToA(__in const std::wstring& wstr)
{
	return StrWideToCode(CP_ACP, wstr);
}

/*++
Description:
	string to wide
	eg:
	"Hello UNONE" => L"Hello UNONE"
Arguments:
	str - string
Return:
	wide string
--*/
std::wstring StrToW(__in const std::string& str)
{
	return StrCodeToWide(CP_ACP, str);
}

/*++
Description:
	wide to acp (The current system Windows ANSI code page, CP_ACP)
	eg:
	L"Hello UNONE" => "Hello UNONE"
Arguments:
	wstr - wide string
Return:
	string
--*/
std::string StrWideToACP(__in const std::wstring& wstr)
{
	return StrWideToCode(CP_ACP, wstr);
}

/*++
Description:
	wide to utf8 (The UTF-8 code page, CP_UTF8)
	eg:
	L"Hello UNONE" => "Hello UNONE"
Arguments:
	wstr - wide string
Return:
	string
--*/
std::string StrWideToUTF8(__in const std::wstring& wstr)
{
	return StrWideToCode(CP_UTF8, wstr);
}

/*++
Description:
	wide to code (The custom code page)
Arguments:
	wstr - wide string
Return:
	string
--*/
std::string StrWideToCode(__in unsigned int code, __in const std::wstring& wstr)
{
	try {
		if (wstr.empty()) return "";
		int templen = WideCharToMultiByte(code, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
		if (!templen) return "";
		char* tempstr = new(std::nothrow) char[templen];
		if (!tempstr) return "";
		memset(tempstr, 0, templen);
		WideCharToMultiByte(code, 0, wstr.c_str(), -1, tempstr, templen, NULL, NULL);
		std::string str(tempstr);
		delete[] tempstr;
		return str;
	} catch (...) {
		return "";
	}
}

/*++
Description:
	acp to wide
Arguments:
	str - string
Return:
	wide string
--*/
std::wstring StrACPToWide(__in const std::string& str)
{
	return StrCodeToWide(CP_ACP, str);
}

/*++
Description:
	acp to utf8
Arguments:
	str - string
Return:
	utf8 string
--*/
std::string StrACPToUTF8(__in const std::string& str)
{
	return StrCodeToCode(CP_UTF8, CP_ACP, str);
}

/*++
Description:
	acp to wide
Arguments:
	str - string
Return:
	string
--*/
std::string StrACPToCode(__in unsigned int code, __in const std::string& str)
{
	return StrCodeToCode(code, CP_ACP, str);
}

/*++
Description:
	acp to wide
Arguments:
	str - string
Return:
	wide string
--*/
std::wstring StrUTF8ToWide(__in const std::string& str)
{
	return StrCodeToWide(CP_UTF8, str);
}

/*++
Description:
	utf8 to acp
Arguments:
	str - string
Return:
	string
--*/
std::string StrUTF8ToACP(__in const std::string& str)
{
	return StrCodeToCode(CP_ACP, CP_UTF8, str);
}

/*++
Description:
	utf8 to code
Arguments:
	str - string
Return:
	string
--*/
std::string StrUTF8ToCode(__in unsigned int code, __in const std::string& str)
{
	return StrCodeToCode(code, CP_UTF8, str);
}


/*++
Description:
	code to wide
Arguments:
	str - string
Return:
	string
--*/
std::wstring StrCodeToWide(__in unsigned int code, __in const std::string& str)
{
	try {
		if (str.empty()) return L"";
		int templen = MultiByteToWideChar(code, 0, str.c_str(), -1, NULL, 0);
		if (!templen) return L"";
		wchar_t* tempstr = new(std::nothrow) wchar_t[templen*2];
		if (!tempstr) return L"";
		memset(tempstr, 0, templen*2);
		MultiByteToWideChar(code, 0, str.c_str(), -1, tempstr, templen);
		std::wstring wstr(tempstr);
		delete[] tempstr;
		return wstr;
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	code to code (The custom code page)
	https://docs.microsoft.com/en-us/windows/desktop/intl/code-page-identifiers
Arguments:
	str - string
Return:
	string
--*/
std::string StrCodeToCode(__in unsigned int code_dst, __in unsigned int code_src, __in const std::string& str)
{
	try {
		if (str.empty()) return "";
		int templen = MultiByteToWideChar(code_src, 0, str.c_str(), -1, NULL, 0);
		if (!templen) return "";
		wchar_t* tempstr = new(std::nothrow) wchar_t[templen*2];
		if (!tempstr) return "";
		memset(tempstr, 0, templen*2);
		MultiByteToWideChar(code_src, 0, str.c_str(), -1, tempstr, templen);
		templen = WideCharToMultiByte(code_dst, 0, tempstr, -1, NULL, 0, NULL, NULL);
		if (!templen) {
			delete[] tempstr;
			return "";
		}
		char* tempstr2 = new(std::nothrow) char[templen];
		if (!tempstr2) {
			delete[] tempstr;
			return "";
		}
		memset(tempstr2, 0, templen);
		WideCharToMultiByte(code_dst, 0, tempstr, -1, tempstr2, templen, NULL, NULL);
		std::string result(tempstr2);
		delete[] tempstr;
		delete[] tempstr2;
		return std::move(result);
	} catch (...) {
		return "";
	}
}

/*++
Description:
	compare two string(_stricmp == 0)
Arguments:
	str1 - string
	str2 - string
Return:
	bool
--*/
bool StrCompareIA(__in const std::string& str1, __in const std::string& str2)
{
	return _stricmp(str1.c_str(), str2.c_str()) == 0;
}

/*++
Description:
	compare two string(_wcsicmp == 0)
Arguments:
	wstr1 - wstring
	wstr2 - wstring
Return:
	bool
--*/
bool StrCompareIW(__in const std::wstring& wstr1, __in const std::wstring& wstr2)
{
	return _wcsicmp(wstr1.c_str(), wstr2.c_str()) == 0;
}

/*++
Description:
	compare two string with wildchar pattern
Arguments:
	str - string
	wild - wildchar
Return:
	bool
--*/
bool StrWildCompareA(__in const std::string& str, __in const std::string& wild)
{
	return WildCmpA(str.c_str(), wild.c_str(), false);
}

/*++
Description:
	compare two string with wildchar pattern
Arguments:
	wstr - wstring
	wild - wildchar
Return:
	bool
--*/
bool StrWildCompareW(__in const std::wstring& wstr, __in const std::wstring& wild)
{
	return WildCmpW(wstr.c_str(), wild.c_str(), false);
}

/*++
Description:
	 compare two string with wildchar pattern (case insensitive)
Arguments:
	str - string
	wild - wildchar
Return:
	bool
--*/
bool StrWildCompareIA(__in const std::string& str, __in const std::string& wild)
{
	return WildCmpA(str.c_str(), wild.c_str(), true);
}

/*++
Description:
	compare two string with wildchar pattern (case insensitive)
Arguments:
	wstr - wstring
	wild - wildchar
Return:
	bool
--*/
bool StrWildCompareIW(__in const std::wstring& wstr, __in const std::wstring& wild)
{
	return WildCmpW(wstr.c_str(), wild.c_str(), true);
}

/*++
Description:
	compare two string with delimiter pattern
Arguments:
	str1 - string one
	str2 - string two
	delimiter - delimiter, default .
Return:
	int, 0(equal) -1(little than) 1(great than)
--*/
int StrDelimitCompareA(__in const std::string& str1, __in const std::string& str2, __in const std::string& delimiter)
{
	return StrDelimitCompareW(StrToW(str1), StrToW(str2), StrToW(delimiter));
}

/*++
Description:
	compare two string with delimiter pattern
Arguments:
	str1 - string one
	str2 - string two
	delimiter - delimiter, default .
Return:
	int, 0(equal) -1(little than) 1(great than)
--*/
int StrDelimitCompareW(__in const std::wstring& str1, __in const std::wstring& str2, __in const std::wstring& delimiter)
{
	bool e1 = str1.empty();
	bool e2 = str2.empty();
	if (e1 && !e2) {
		return -1;
	}
	if (!e1 && e2) {
		return 1;
	}
	if (e1 && e2) {
		return 0;
	}
	int result = 0;
	std::vector<std::wstring> vec1, vec2;
	StrSplitW(str1, delimiter, vec1);
	StrSplitW(str2, delimiter, vec2);
	size_t count = MIN(vec1.size(), vec2.size());
	for (size_t i = 0; i < count; i++)	{
		int64_t temp1 = StrToInteger64W(vec1[i]);
		int64_t temp2 = StrToInteger64W(vec2[i]);
		if (temp1 != temp2) {
			result = (temp1 - temp2) < 0 ? -1 : 1;
			break;
		}
	}
	return result;
}

/*++
Description:
	format string
Arguments:
	str - formated wstring
	formats - format control chars
	... - variable parameter
Return:
	bool
--*/
bool StrFormatA(__out std::string& str, __in const char* formats, ...)
{
	try {
		va_list lst;
		va_start(lst,formats);
		str = StrFormatVaListA(formats, lst);
		va_end(lst);
	} catch (std::exception& e) {
		str.clear();
		UNONE_ERROR("c++ exception: %s", e.what());
		return false;
	} catch (...) {
		str.clear();
		UNONE_ERROR("c++ exception: unknown");
		return false;
	}
	return true;
}

/*++
Description:
	format string
Arguments:
	formats - format control chars
	... - variable parameter
Return:
	formated string
--*/
std::string StrFormatA(__in const char* formats, ...)
{
	std::string str;
	try {
		va_list lst;
		va_start(lst,formats);
		str = StrFormatVaListA(formats, lst);
		va_end(lst);
	} catch (std::exception& e) {
		str.clear();
		UNONE_ERROR("c++ exception: %s", e.what());
	} catch (...) {
		str.clear();
		UNONE_ERROR("c++ exception: unknown");
	}
	return str;
}

/*++
Description:
	format wstring
Arguments:
	wstr - formated wstring
	formats - format control chars
	... - variable parameter
Return:
	bool
--*/
bool StrFormatW(__out std::wstring& wstr, __in const wchar_t* formats, ...)
{
	try {
		va_list lst;
		va_start(lst,formats);
		wstr = StrFormatVaListW(formats, lst);
		va_end(lst);
	} catch (std::exception& e) {
		wstr.clear();
		UNONE_ERROR("c++ exception: %s", e.what());
		return false;
	} catch (...) {
		wstr.clear();
		UNONE_ERROR("c++ exception: unknown");
		return false;
	}
	return true;
}

/*++
Description:
	format wstring
Arguments:
	formats - format control chars
	... - variable parameter
Return:
	formated wstring
--*/
std::wstring StrFormatW(__in const wchar_t* formats, ...)
{
	std::wstring str;
	try {
		va_list lst;
		va_start(lst,formats);
		str = StrFormatVaListW(formats, lst);
		va_end(lst);
	} catch (std::exception& e) {
		str.clear();
		UNONE_ERROR("c++ exception: %s", e.what());
	} catch (...) {
		str.clear();
		UNONE_ERROR("c++ exception: unknown");
	}
	return str;
}

/*++
Description:
	format string with va_list
Arguments:
	formats - format control chars
	lst - variable parameter list
Return:
	formated wstring
--*/
std::string StrFormatVaListA(__in const char* formats, __in va_list lst)
{
	try {
		int bufsize = _vscprintf(formats, lst);
		if (bufsize == 0)
			return "";
		bufsize += sizeof(char);
		char* buffer = (char*) malloc(bufsize);
		if (buffer == NULL)
			return "";
		memset(buffer, 0, bufsize);
		_vsnprintf_s(buffer, bufsize/sizeof(char), (bufsize/sizeof(char))-1, formats, lst);
		std::string str(buffer);
		free(buffer);
		return std::move(str);
	} catch (...) {
		return "";
	}
}

/*++
Description:
	format wstring with va_list
Arguments:
	formats - format control chars
	lst - variable parameter list
Return:
	formated string
--*/
std::wstring StrFormatVaListW(__in const wchar_t* formats, __in va_list lst)
{
	try {
		int bufsize = _vscwprintf(formats, lst) * sizeof(wchar_t);
		if (bufsize == 0)
			return L"";
		bufsize += sizeof(wchar_t);
		wchar_t* buffer = (wchar_t*) malloc(bufsize);
		if (buffer == NULL)
			return L"";
		memset(buffer, 0, bufsize);
		_vsnwprintf_s(buffer, bufsize/sizeof(wchar_t), (bufsize/sizeof(wchar_t))-1, formats, lst);
		std::wstring str(buffer);
		free(buffer);
		return std::move(str);
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	check str2 is sub string of str1
Arguments:
	str1 - primary
	str2 - sub
Return:
	bool
--*/
bool StrContainA(__in const std::string& str1, __in const std::string& str2)
{
	return strstr(str1.c_str(), str2.c_str()) != nullptr;
}

/*++
Description:
	check wstr2 is substring of wstr1
Arguments:
	wstr1 - primary
	wstr2 - sub
Return:
	bool
--*/
bool StrContainW(__in const std::wstring& wstr1, __in const std::wstring& wstr2)
{
	return wcsstr(wstr1.c_str(), wstr2.c_str()) != nullptr;
}

/*++
Description:
	check str2 is sub string of str1(case insensitive)
Arguments:
	str1 - primary
	str2 - sub
Return:
	bool
--*/
bool StrContainIA(__in const std::string& str1, __in const std::string& str2)
{
	return StrIndexIA(str1.c_str(), str2.c_str()) != nullptr;
}

/*++
Description:
	check wstr2 is substring of wstr1(case insensitive)
Arguments:
	wstr1 - primary
	wstr2 - sub
Return:
	bool
--*/
bool StrContainIW(__in const std::wstring& wstr1, __in const std::wstring& wstr2)
{
	return StrIndexIW(wstr1.c_str(), wstr2.c_str()) != nullptr;
}

/*++
Description:
	str2 index pointer of str1, just like strstr(case insensitive)
Arguments:
	str1 - primary
	str2 - sub
Return:
	sub index ptr
--*/
char* StrIndexIA(__in const char* str1, __in const char* str2)
{
	char *cp = (char *) str1;
	char *s1, *s2;
	if ( !*str2 ) return((char *)str1);
	while (*cp) {
		s1 = cp;
		s2 = (char *) str2;
		while ( *s1 && *s2 && !(tolower(*s1)-tolower(*s2)) ) s1++, s2++;
		if (!*s2) return(cp);
		cp++;
	}
	return(nullptr);
}

/*++
Description:
	str2 index pointer of str1, just like wcsstr(case insensitive)
Arguments:
	str1 - primary
	str2 - sub
Return:
	sub index ptr
--*/
wchar_t* StrIndexIW(__in const wchar_t* str1, __in const wchar_t* str2)
{
	wchar_t *cp = (wchar_t *) str1;
	wchar_t *s1, *s2;
	if ( !*str2 ) return((wchar_t *)str1);
	while (*cp) {
		s1 = cp;
		s2 = (wchar_t *) str2;
		while ( *s1 && *s2 && !(tolower(*s1)-tolower(*s2)) ) s1++, s2++;
		if (!*s2) return(cp);
		cp++;
	}
	return(nullptr);
}

/*++
Description:
	str2 index pointer of str1, just like STL find(case insensitive)
Arguments:
	str1 - primary
	str2 - sub
Return:
	position
--*/
size_t StrIndexIA(__in const std::string& str1, __in const std::string& str2)
{
	const char* primary = str1.c_str();
	char* subptr = StrIndexIA(str1.c_str(), str2.c_str());
	if (subptr == nullptr) {
		return std::string::npos;
	}
	return (size_t)(subptr - primary);
}

/*++
Description:
	str2 index pointer of str1, just like stl find(case insensitive)
Arguments:
	str1 - primary
	str2 - sub
Return:
	position
--*/
size_t StrIndexIW(__in const std::wstring& str1, __in const std::wstring& str2)
{
	const wchar_t* primary = str1.c_str();
	wchar_t* subptr = StrIndexIW(str1.c_str(), str2.c_str());
	if (subptr == nullptr) {
		return std::wstring::npos;
	}
	return (size_t)(subptr - primary);
}

/*++
Description:
	trim string
Arguments:
	str - primary
	charlist - trim chars
Return:
	trimmed string
--*/
std::string StrTrimA(__in const std::string& str, __in const std::string& charlist)
{
	try {
		if(!str.empty())
			return StrTrimLeftA(StrTrimRightA(str,charlist),charlist); 
		else
			return str;
	} catch (...) {
		return "";
	}
}

/*++
Description:
	trim string
Arguments:
	str - primary
	charlist - trim chars
Return:
	trimmed string
--*/
std::wstring StrTrimW(__in const std::wstring& str, __in const std::wstring& charlist)
{
	try {
		if(!str.empty())
			return StrTrimLeftW(StrTrimRightW(str,charlist),charlist); 
		else
			return str;
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	trim left string
Arguments:
	str - primary
	charlist - trim chars
Return:
	trimmed string
--*/
std::string StrTrimLeftA(__in const std::string& str, __in const std::string& charlist)
{
	if(!str.empty())
		return str.substr(str.find_first_not_of(charlist)); 
	else
		return str;
}

/*++
Description:
	trim left string
Arguments:
	str - primary
	charlist - trim chars
Return:
	trimmed string
--*/
std::wstring StrTrimLeftW(__in const std::wstring& str, __in const std::wstring& charlist)
{
	if(!str.empty())
		return str.substr(str.find_first_not_of(charlist)); 
	else
		return str;
}

/*++
Description:
	trim right string
Arguments:
	str - primary
	charlist - trim chars
Return:
	trimmed string
--*/
std::string StrTrimRightA(__in const std::string& str, __in const std::string& charlist)
{
	if(!str.empty())
		return str.substr(0,str.find_last_not_of(charlist)+1); 
	else
		return str;
}

/*++
Description:
	trim right string
Arguments:
	str - primary
	charlist - trim chars
Return:
	trimmed string
--*/
std::wstring StrTrimRightW(__in const std::wstring& str, __in const std::wstring& charlist)
{
	if(!str.empty())
		return str.substr(0,str.find_last_not_of(charlist)+1); 
	else
		return str;
}

/*++
Description:
	split string
Arguments:
	str - primary
	sep - separator string
	vec - result
Return:
	bool
--*/
bool StrSplitA(__in std::string str, __in const std::string& sep, __out std::vector<std::string>& vec)
{
	try {
		size_t pos = 0;
		if (!str.empty()) {
			do {
				pos = str.find(sep);
				if (pos == std::string::npos) {
					vec.push_back(str);
					break;
				}
				vec.push_back(str.substr(0, pos));
				str = str.substr(pos+sep.size());
			} while (true);
		}
		return true;
	} catch (...) {
		vec.clear();
		return false;
	}
}

/*++
Description:
	split string
Arguments:
	str - primary
	sep - separator string
	vec - result
Return:
	bool
--*/
bool StrSplitW(__in std::wstring str, __in const std::wstring& sep, __out std::vector<std::wstring>& vec)
{
	try {
		size_t pos = 0;
		if (!str.empty()) {
			do {
				pos = str.find(sep);
				if (pos == std::wstring::npos) {
					vec.push_back(str);
					break;
				}
				vec.push_back(str.substr(0, pos));
				str = str.substr(pos+sep.size());
			} while (true);
		}
		return true;
	} catch (...) {
		vec.clear();
		return false;
	}
}

/*++
Description:
	split string(case insensitive)
Arguments:
	str - primary
	sep - separator string
	vec - result
Return:
	bool
--*/
bool StrSplitIA(__in std::string str, __in const std::string& sep, __out std::vector<std::string>& vec)
{
	try {
		size_t pos = 0;
		if (!str.empty()) {
			do {
				pos = StrIndexIA(str, sep);
				if (pos == std::string::npos) {
					vec.push_back(str);
					break;
				}
				vec.push_back(str.substr(0, pos));
				str = str.substr(pos+sep.size());
			} while (true);
		}
		return true;
	} catch (...) {
		vec.clear();
		return false;
	}
}

/*++
Description:
	split string(case insensitive)
Arguments:
	str - primary
	sep - separator string
	vec - result
Return:
	bool
--*/
UNONE_API bool StrSplitIW(__in std::wstring str, __in const std::wstring& sep, __out std::vector<std::wstring>& vec)
{
	try {
		size_t pos = 0;
		if (!str.empty()) {
			do {
				pos = StrIndexIW(str, sep);
				if (pos == std::wstring::npos) {
					vec.push_back(str);
					break;
				}
				vec.push_back(str.substr(0, pos));
				str = str.substr(pos+sep.size());
			} while (true);
		}
		return true;
	} catch (...) {
		vec.clear();
		return false;
	}
}

/*++
Description:
	split string to lines(CRLF/LF/CR)
Arguments:
	str - primary
	lines - result
Return:
	bool
--*/
bool StrSplitLinesA(__in std::string str, __out std::vector<std::string>& lines)
{
	try {
		size_t pos = 0;
		if (!str.empty()) {
			do {
				pos = str.find('\n');
				if (pos == std::string::npos) {
					if (!str.empty() && str[str.size()-1] == '\r') {
						lines.push_back(str.substr(0, str.size()-1));
					} else {
						lines.push_back(str);
					}
					break;
				}
				std::string&& line = str.substr(0, pos);
				if (line[line.size()-1] == '\r') {
					lines.push_back(line.substr(0, line.size()-1));
				} else {
					lines.push_back(line);
				}
				str = str.substr(pos+1);
			} while (true);
		}
		return true;
	} catch (...) {
		lines.clear();
		return false;
	}
}

/*++
Description:
	split string to lines(CRLF/LF/CR)
Arguments:
	str - primary
	lines - result
Return:
	bool
--*/
bool StrSplitLinesW(__in std::wstring str, __out std::vector<std::wstring>& lines)
{
	try {
		size_t pos = 0;
		if (!str.empty()) {
			do {
				pos = str.find(L'\n');
				if (pos == std::wstring::npos) {
					if (!str.empty() && str[str.size()-1] == L'\r') {
						lines.push_back(str.substr(0, str.size()-1));
					} else {
						lines.push_back(str);
					}
					break;
				}
				std::wstring&& line = str.substr(0, pos);
				if (line[line.size()-1] == L'\r') {
					lines.push_back(line.substr(0, line.size()-1));
				} else {
					lines.push_back(line);
				}
				str = str.substr(pos+1);
			} while (true);
		}
		return true;
	} catch (...) {
		lines.clear();
		return false;
	}
}

/*++
Description:
	truncate string
Arguments:
	str - primary
	startsep - start separator
	endsep - end separator
Return:
	truncated string
--*/
std::string StrTruncateA(__in const std::string& str, __in const std::string& startsep, __in const std::string& endsep)
{
	try {
		size_t start = str.find(startsep);
		if (start == std::string::npos)
			return "";
		start += startsep.size();
		size_t end = str.find(endsep,start);
		if (end == std::string::npos)
			return "";
		if (end <= start)
			return "";
		return str.substr(start, end-start);
	} catch (...) {
		return "";
	}
}

/*++
Description:
	truncate string
Arguments:
	str - primary
	startsep - start separator
	endsep - end separator
Return:
	truncated string
--*/
UNONE_API std::wstring StrTruncateW(__in const std::wstring& str, __in const std::wstring& startsep, __in const std::wstring& endsep)
{
	try {
		size_t start = str.find(startsep);
		if (start == std::wstring::npos)
			return L"";
		start += startsep.size();
		size_t end = str.find(endsep,start);
		if (end == std::wstring::npos)
			return L"";
		if (end <= start)
			return L"";
		return str.substr(start, end-start);
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	truncate string(case insensitive)
Arguments:
	str - primary
	startsep - start separator
	endsep - end separator
Return:
	truncated string
--*/
std::string StrTruncateIA(__in const std::string& str, __in std::string startsep, __in std::string endsep)
{
	try {
		std::string tempstr(str);
		StrUpperA(tempstr);
		StrUpperA(startsep);
		StrUpperA(endsep);
		size_t start = tempstr.find(startsep);
		if (start == std::string::npos)
			return "";
		start += startsep.size();
		size_t end = tempstr.find(endsep,start);
		if (end == std::string::npos)
			return "";
		if (end <= start)
			return "";
		return str.substr(start, end-start);
	} catch (...) {
		return "";
	}
}

/*++
Description:
	truncate string(case insensitive)
Arguments:
	str - primary
	startsep - start separator
	endsep - end separator
Return:
	truncated string
--*/
std::wstring StrTruncateIW(__in const std::wstring& str, __in std::wstring startsep, __in std::wstring endsep)
{
	try {
		std::wstring tempstr(str);
		StrUpperW(tempstr);
		StrUpperW(startsep);
		StrUpperW(endsep);
		size_t start = tempstr.find(startsep);
		if (start == std::wstring::npos)
			return L"";
		start += startsep.size();
		size_t end = tempstr.find(endsep,start);
		if (end == std::wstring::npos)
			return L"";
		if (end <= start)
			return L"";
		return str.substr(start, end-start);
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	join string
Arguments:
	vec - primary string list
	sep - separator
Return:
	joined string
--*/
std::string StrJoinA(__in const std::vector<std::string>& vec, __in const std::string& sep)
{
	try {
		std::string str;
		size_t size = vec.size();
		for (size_t i=0; i<size; i++) {
			str.append(vec[i]);
			if (i != size-1)
				str.append(sep);
		}
		return str;
	} catch (...) {
		return "";
	}
}

/*++
Description:
	join wide string
Arguments:
	vec - primary string list
	sep - separator
Return:
	joined string
--*/
std::wstring StrJoinW(__in const std::vector<std::wstring>& vec, __in const std::wstring& sep)
{
	try {
		std::wstring str;
		size_t size = vec.size();
		for (size_t i = 0; i < size; i++) {
			str.append(vec[i]);
			if (i != size-1)
				str.append(sep);
		}
		return str;
	} catch (...) {
		return L"";
	}
}


/*++
Description:
	insert separator to string interval
Arguments:
	str - primary
	interval - interval
	sep - separator
Return:
	inserted string
--*/
std::string StrInsertA(__in const std::string& str, __in size_t interval, __in const std::string& sep)
{
	std::string result;
	for (size_t i = 0; i < str.size(); i += interval) {
		if (i > 0)
			result.append(sep);
		result.append(str.substr(i, interval));
	}
	return result;
}

/*++
Description:
	insert separator to wide string interval
Arguments:
	str - primary
	interval - interval
	sep - separator
Return:
	inserted string
--*/
std::wstring StrInsertW(__in const std::wstring& str, __in size_t interval, __in const std::wstring& sep)
{
	std::wstring result;
	for (size_t i=0; i<str.size(); i+=interval) {
		if (i > 0)
			result.append(sep);
		result.append(str.substr(i, interval));
	}
	return result;
}

/*++
Description:
	reverse string interval
	eg:
	if interval eq 2/4 => little/big endian convert
Arguments:
	str - primary
	interval - interval
Return:
	reversed string
--*/
std::string StrReverseA(__in const std::string& str, __in size_t interval)
{
	if (interval == -1) {
		std::string str2(str);
		std::reverse(str2.begin(), str2.end());
		return str2;
	}
	std::string result;
	size_t size = str.size();
	for (size_t i = 0; i < size; i += interval) {
		if (i + interval > size)
			interval = size - i;
		std::string str2(&str[i], interval);
		std::reverse(str2.begin(), str2.end());
		result.append(str2);
	}
	return result;
}

/*++
Description:
	reverse string interval
	eg:
	if interval eq 2/4 => little/big endian convert
Arguments:
	str - primary
	interval - interval
Return:
	reversed string
--*/
std::wstring StrReverseW(__in const std::wstring& str, __in size_t interval)
{
	if (interval == -1) {
		std::wstring str2(str);
		std::reverse(str2.begin(), str2.end());
		return str2;
	}
	std::wstring result;
	size_t size = str.size();
	for (size_t i = 0; i < size; i += interval) {
		if (i + interval > size)
			interval = size - i;
		std::wstring str2(&str[i], interval);
		std::reverse(str2.begin(), str2.end());
		result.append(str2);
	}
	return result;
}

/*++
Description:
	repeat string
Arguments:
	str - element
	count - repeat count
Return:
	inserted string
--*/
std::string StrRepeatA(__in const std::string& str, __in size_t count)
{
	std::string result;
	for (size_t i = 0; i < count; i++) {
		result.append(str);
	}
	return result;
}

/*++
Description:
	repeat wide string
Arguments:
	str - element
	count - repeat count
Return:
	inserted string
--*/
std::wstring StrRepeatW(__in const std::wstring& str, __in size_t count)
{
	std::wstring result;
	for (size_t i = 0; i < count; i++) {
		result.append(str);
	}
	return result;
}

/*++
Description:
	replace string
Arguments:
	source - source string
	pattern - pattern string
	replaced - replaced string
Return:
	bool
--*/
bool StrReplaceA(__inout std::string& source, __in const std::string& pattern, __in std::string replaced)
{
	try {
		bool result = false;
		if (source.empty() || pattern.empty())
			return false;
		size_t pos = 0;
		while ((pos = source.find(pattern, pos)) != std::string::npos) {
			source.replace(pos, pattern.size(), replaced);
			pos += replaced.size();
			result = true;
		}
		return result;
	} catch (...) {
		return false;
	}
}

/*++
Description:
	replace wide string
Arguments:
	source - source string
	pattern - pattern string
	replaced - replaced string
Return:
	bool
--*/
bool StrReplaceW(__inout std::wstring& source, __in const std::wstring& pattern, __in std::wstring replaced)
{
	try {
		bool result = false;
		if (source.empty() || pattern.empty())
			return false;
		size_t pos = 0;
		while ((pos = source.find(pattern, pos)) != std::wstring::npos) {
			source.replace(pos, pattern.size(), replaced);
			pos += replaced.size();
			result = true;
		}
		return result;
	} catch (...) {
		return false;
	}
}

/*++
Description:
	replace string(case insensitive)
Arguments:
	source - source string
	pattern - pattern string
	replaced - replaced string
Return:
	bool
--*/
bool StrReplaceIA(__inout std::string& source, __in std::string pattern, __in std::string replaced)
{
	try {
		bool result = false;
		if (source.empty() || pattern.empty())
			return false;
		std::string str = source;
		StrLowerA(str);
		StrLowerA(pattern);
		size_t pos = 0;
		while ((pos = str.find(pattern, pos)) != std::string::npos) {
			source.replace(pos, pattern.size(), replaced);
			str.replace(pos, pattern.size(), replaced);
			pos += replaced.size();
			result = true;
		}
		return result;
	} catch (...) {
		return false;
	}
}

/*++
Description:
	replace wide string(case insensitive)
Arguments:
	source - source string
	pattern - pattern string
	replaced - replaced string
Return:
	bool
--*/
bool StrReplaceIW(__inout std::wstring& source, __in std::wstring pattern, __in std::wstring replaced)
{
	try {
		bool result = false;
		if (source.empty() || pattern.empty())
			return false;
		std::wstring str = source;
		StrLowerW(str);
		StrLowerW(pattern);
		size_t pos = 0;
		while ((pos = str.find(pattern, pos)) != std::wstring::npos) {
			source.replace(pos, pattern.size(), replaced);
			str.replace(pos, pattern.size(), replaced);
			pos += replaced.size();
			result = true;
		}
		return result;
	} catch (...) {
		return false;
	}
}

} //namespace UNONE