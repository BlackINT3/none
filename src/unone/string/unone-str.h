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
#include <string>
#include <set>
#include <vector>
#include <Windows.h>
#include <stdint.h>

namespace	UNONE {

const std::string kHexDigits = "0123456789abcdefABCDEF";
const std::string kHexLowerDigits = "0123456789abcdef";
const std::string kHexUpperDigits = "0123456789ABCDEF";
const std::string kDecDigits = "0123456789";
const std::string kOctDigits = "01234567";
const std::string kBinDigits = "01";

/*
// NAME-CONVENTION-SPEC
//
// str  := multi char string
// mstr := multi char string
// wstr := wide char string
// astr := ANSI_STRING
// ustr := UNICODE_STRING
*/

#ifdef _UNICODE
#define StrLower StrLowerW
#define StrUpper StrUpperW
#define StrToLower StrToLowerW
#define StrToUpper StrToUpperW
#define StrToHex StrToHexW
#define StrToHex64 StrToHex64W
#define StrToInteger StrToIntegerW
#define StrToInteger64 StrToInteger64W
#define StrToDecimal StrToIntegerW
#define StrToDecimal64 StrToInteger64W
#define StrToOctal StrToOctalW
#define StrToOctal64 StrToOctal64W
#define StrToBinary StrToBinaryW
#define StrToBinary64 StrToBinary64W
#define StrCompareI StrCompareIW
#define StrWildCompare StrWildCompareW
#define StrWildCompareI	StrWildCompareIW
#define StrFormat StrFormatW
#define StrFormatVaList StrFormatVaListW
#define StrContain StrContainW
#define StrContainI StrContainIW
#define StrIndexI StrIndexIW
#define StrTrim StrTrimW
#define StrTrimLeft StrTrimLeftW
#define StrTrimRight StrTrimRightW
#define StrSplit StrSplitW
#define StrSplitI StrSplitIW
#define StrSplitLines StrSplitLinesW
#define StrTruncate StrTruncateW
#define StrTruncateI StrTruncateIW
#define StrJoin StrJoinW
#define StrInsert StrInsertW
#define StrRepeat StrRepeatW
#define StrReplace StrReplaceW
#define StrReplaceI StrReplaceIW
#else
#define StrLower StrLowerA
#define StrUpper StrUpperA
#define StrToLower StrToLowerA
#define StrToUpper StrToUpperA
#define StrToHex StrToHexA
#define StrToHex64 StrToHex64A
#define StrToInteger StrToIntegerA
#define StrToInteger64 StrToInteger64A
#define StrToDecimal StrToIntegerA
#define StrToDecimal64 StrToInteger64A
#define StrToOctal StrToOctalA
#define StrToOctal64 StrToOctal64A
#define StrToBinary StrToBinaryA
#define StrToBinary64 StrToBinary64A
#define StrCompareI StrCompareIA
#define StrWildCompare StrWildCompareA
#define StrWildCompareI StrWildCompareIA
#define StrFormat StrFormatA
#define StrFormatVaList StrFormatVaListA
#define StrContain StrContainA
#define StrContainI StrContainIA
#define StrIndexI StrIndexIA
#define StrTrim StrTrimA
#define StrTrimLeft StrTrimLeftA
#define StrTrimRight StrTrimRightA
#define StrSplit StrSplitA
#define StrSplitI StrSplitIA
#define StrSplitLines StrSplitLinesA
#define StrTruncate StrTruncateA
#define StrTruncateI StrTruncateIA
#define StrJoin StrJoinA
#define StrInsert StrInsertA
#define StrRepeat StrRepeatA
#define StrReplace StrReplaceA
#define StrReplaceI StrReplaceIA	
#endif // _UNICODE

#define StrToDecimalA StrToIntegerA
#define StrToDecimal64A StrToInteger64A
#define StrToDecimalW StrToIntegerW
#define StrToDecimal64W StrToInteger64W

UNONE_API void StrLowerA(__inout std::string& str);
UNONE_API void StrLowerW(__inout std::wstring& wstr);
UNONE_API void StrUpperA(__inout std::string& str);
UNONE_API void StrUpperW(__inout std::wstring& wstr);
UNONE_API std::string StrToLowerA(__in const std::string& str);
UNONE_API std::wstring StrToLowerW(__in const std::wstring& wstr);
UNONE_API std::string StrToUpperA(__in const std::string& str);
UNONE_API std::wstring StrToUpperW(__in const std::wstring& wstr);

UNONE_API unsigned int StrToHexA(__in const std::string& str);
UNONE_API unsigned int StrToHexW(__in const std::wstring& wstr);
UNONE_API uint64_t StrToHex64A(__in const std::string& str);
UNONE_API uint64_t StrToHex64W(__in const std::wstring& wstr);
UNONE_API int StrToIntegerA(__in const std::string& str);
UNONE_API int StrToIntegerW(__in const std::wstring& wstr);
UNONE_API int64_t StrToInteger64A(__in const std::string& str);
UNONE_API int64_t StrToInteger64W(__in const std::wstring& wstr);
UNONE_API int StrToOctalA(__in const std::string& str);
UNONE_API int StrToOctalW(__in const std::wstring& wstr);
UNONE_API int64_t StrToOctal64A(__in const std::string& str);
UNONE_API int64_t StrToOctal64W(__in const std::wstring& wstr);
UNONE_API int StrToBinaryA(__in const std::string& str);
UNONE_API int StrToBinaryW(__in const std::wstring& wstr);
UNONE_API int64_t StrToBinary64A(__in const std::string& str);
UNONE_API int64_t StrToBinary64W(__in const std::wstring& wstr);
UNONE_API std::wstring StrUstrToWide(__in void* ustr);
UNONE_API std::string StrAstrToStr(__in void* astr);
UNONE_API std::string StrStreamToHexStrA(__in const std::string& stream);
UNONE_API std::string StrStreamToHexStrW(__in const std::wstring& stream);
UNONE_API std::string StrHexStrToStreamA(__in const std::string& hexstr);
UNONE_API std::wstring StrHexStrToStreamW(__in const std::string& hexstr);

UNONE_API std::string StrToA(__in const std::wstring& wstr);
UNONE_API std::wstring StrToW(__in const std::string& str);
UNONE_API std::string StrWideToACP(__in const std::wstring& wstr);
UNONE_API std::string StrWideToUTF8(__in const std::wstring& wstr);
UNONE_API std::string StrWideToCode(__in unsigned int code, __in const std::wstring& wstr);
UNONE_API std::wstring StrACPToWide(__in const std::string& str);
UNONE_API std::string StrACPToUTF8(__in const std::string& str);
UNONE_API std::string StrACPToCode(__in unsigned int code, __in const std::string& str);
UNONE_API std::wstring StrUTF8ToWide(__in const std::string& str);
UNONE_API std::string StrUTF8ToACP(__in const std::string& str);
UNONE_API std::string StrUTF8ToCode(__in unsigned int code, __in const std::string& str);
UNONE_API std::wstring StrCodeToWide(__in unsigned int code, __in const std::string& str);
UNONE_API std::string StrCodeToCode(__in unsigned int code_dst, __in unsigned int code_src, __in const std::string& str);

UNONE_API bool StrCompareIA(__in const std::string& str1, __in const std::string& str2);
UNONE_API bool StrCompareIW(__in const std::wstring& wstr1, __in const std::wstring& wstr2);
UNONE_API bool StrWildCompareA(__in const std::string& str, __in const std::string& wild);
UNONE_API bool StrWildCompareW(__in const std::wstring& wstr, __in const std::wstring& wild);
UNONE_API bool StrWildCompareIA(__in const std::string& str, __in const std::string& wild);
UNONE_API bool StrWildCompareIW(__in const std::wstring& wstr, __in const std::wstring& wild);
UNONE_API int StrDelimitCompareA(__in const std::string& str1, __in const std::string& str2, __in const std::string& delimiter=".");
UNONE_API int StrDelimitCompareW(__in const std::wstring& str1, __in const std::wstring& str2, __in const std::wstring& delimiter = L".");

UNONE_API bool StrFormatA(__out std::string& str, __in const char* formats, ...);
UNONE_API std::string StrFormatA(__in const char* formats, ...);
UNONE_API bool StrFormatW(__out std::wstring& wstr, __in const wchar_t* formats, ...);
UNONE_API std::wstring StrFormatW(__in const wchar_t* formats, ...);
UNONE_API std::string StrFormatVaListA(__in const char* formats, __in va_list lst);
UNONE_API std::wstring StrFormatVaListW(__in const wchar_t* formats, __in va_list lst);

UNONE_API bool StrContainA(__in const std::string& str1, __in const std::string& str2);
UNONE_API bool StrContainW(__in const std::wstring& wstr1, __in const std::wstring& wstr2);
UNONE_API bool StrContainIA(__in const std::string& str1, __in const std::string& str2);
UNONE_API bool StrContainIW(__in const std::wstring& wstr1, __in const std::wstring& wstr2);
UNONE_API char* StrIndexIA(__in const char* str1, __in const char* str2);
UNONE_API wchar_t* StrIndexIW(__in const wchar_t* str1, __in const wchar_t* str2);
UNONE_API size_t StrIndexIA(__in const std::string& str1, __in const std::string& str2);
UNONE_API size_t StrIndexIW(__in const std::wstring& str1, __in const std::wstring& str2);

UNONE_API std::string StrTrimA(__in const std::string& str, __in const std::string& charlist = " \n\r\t");
UNONE_API std::wstring StrTrimW(__in const std::wstring& str, __in const std::wstring& charlist = L" \n\r\t");
UNONE_API std::string StrTrimLeftA(__in const std::string& str, __in const std::string& charlist = " \n\r\t");
UNONE_API std::wstring StrTrimLeftW(__in const std::wstring& str, __in const std::wstring& charlist = L" \n\r\t");
UNONE_API std::string StrTrimRightA(__in const std::string& str, __in const std::string& charlist = " \n\r\t");
UNONE_API std::wstring StrTrimRightW(__in const std::wstring& str, __in const std::wstring& charlist = L" \n\r\t");

UNONE_API bool StrSplitA(__in std::string str, __in const std::string& sep, __out std::vector<std::string>& vec);
UNONE_API bool StrSplitW(__in std::wstring str, __in const std::wstring& sep, __out std::vector<std::wstring>& vec);
UNONE_API bool StrSplitIA(__in std::string str, __in const std::string& sep, __out std::vector<std::string>& vec);
UNONE_API bool StrSplitIW(__in std::wstring str, __in const std::wstring& sep, __out std::vector<std::wstring>& vec);
UNONE_API bool StrSplitLinesA(__in std::string str, __out std::vector<std::string>& lines);
UNONE_API bool StrSplitLinesW(__in std::wstring str, __out std::vector<std::wstring>& lines);
UNONE_API std::string StrTruncateA(__in const std::string& str, __in const std::string& startsep, __in const std::string& endsep);
UNONE_API std::wstring StrTruncateW(__in const std::wstring& str, __in const std::wstring& startsep, __in const std::wstring& endsep);
UNONE_API std::string StrTruncateIA(__in const std::string& str, __in std::string startsep, __in std::string endsep);
UNONE_API std::wstring StrTruncateIW(__in const std::wstring& str, __in std::wstring startsep, __in std::wstring endsep);

UNONE_API std::string StrJoinA(__in const std::vector<std::string>& vec, __in const std::string& sep = "");
UNONE_API std::wstring StrJoinW(__in const std::vector<std::wstring>& vec, __in const std::wstring& sep = L"");

UNONE_API std::string StrInsertA(__in const std::string& str, __in size_t interval, __in const std::string& sep = "");
UNONE_API std::wstring StrInsertW(__in const std::wstring& str, __in size_t interval, __in const std::wstring& sep = L"");

UNONE_API std::string StrReverseA(__in const std::string& str, __in size_t interval = -1);
UNONE_API std::wstring StrReverseW(__in const std::wstring& str, __in size_t interval = -1);

UNONE_API std::string StrRepeatA(__in const std::string& str, __in size_t count);
UNONE_API std::wstring StrRepeatW(__in const std::wstring& str, __in size_t count);

UNONE_API bool StrReplaceA(__inout std::string& source, __in const std::string& pattern, __in std::string replaced = "");
UNONE_API bool StrReplaceW(__inout std::wstring& source, __in const std::wstring& pattern, __in std::wstring replaced = L"");
UNONE_API bool StrReplaceIA(__inout std::string& source, __in std::string pattern, __in std::string replaced = "");
UNONE_API bool StrReplaceIW(__inout std::wstring& source, __in std::wstring pattern, __in std::wstring replaced = L"");

} // namespace UNONE
