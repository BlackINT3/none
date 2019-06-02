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
#include "unone-str-test.h"

TEST(TestStrBaseOps, StrTest)
{
	{// lower test
		std::string str = "ABCdefghIjk";
		std::wstring wstr = L"ABCdefghIjk";
		EXPECT_TRUE(UNONE::StrToLower(wstr) == _T("abcdefghijk"));
		EXPECT_TRUE(UNONE::StrToLowerA(str) == "abcdefghijk");
		EXPECT_TRUE(UNONE::StrToLowerW(wstr) == L"abcdefghijk");
		UNONE::StrLowerA(str);
		UNONE::StrLowerW(wstr);
		EXPECT_TRUE(str == "abcdefghijk");
		EXPECT_TRUE(wstr == L"abcdefghijk");
		EXPECT_FALSE(str == "ABCDEFGHIJK");
		EXPECT_FALSE(wstr == L"ABCDEFGHIJK");
	}

	{// upper test
		std::string str = "ABCdefghIjk";
		std::wstring wstr = L"ABCdefghIjk";
		EXPECT_TRUE(UNONE::StrToUpperA(str) == "ABCDEFGHIJK");
		EXPECT_TRUE(UNONE::StrToUpperW(wstr) == L"ABCDEFGHIJK");
		UNONE::StrUpperA(str);
		UNONE::StrUpperW(wstr);
		EXPECT_TRUE(str == "ABCDEFGHIJK");
		EXPECT_TRUE(wstr == L"ABCDEFGHIJK");
		EXPECT_FALSE(str == "abcdefghijk");
		EXPECT_FALSE(wstr == L"abcdefghijk");
	}

	{// hex number convert test
		std::string str = "123ABC";
		std::wstring wstr = L"123ABC";
		std::string str64 = "123456ABCDEF";
		std::wstring wstr64 = L"123456ABCDEF";

		EXPECT_TRUE(UNONE::StrToHexA(str) == 0x123ABC);
		EXPECT_TRUE(UNONE::StrToHexW(wstr) == 0x123ABC);
		EXPECT_FALSE(UNONE::StrToHexA(str) == 0x123456ABCDEF);
		EXPECT_TRUE(UNONE::StrToHex64A(str) == 0x123ABC);
		EXPECT_TRUE(UNONE::StrToHex64W(wstr) == 0x123ABC);
		EXPECT_TRUE(UNONE::StrToHex64A(str64) == 0x123456ABCDEF);
		EXPECT_TRUE(UNONE::StrToHex64W(wstr64) == 0x123456ABCDEF);
	}

	{// integer number convert test
		std::string str = "12356789";
		std::wstring wstr = L"12356789";
		std::string str64 = "123567890111111";
		std::wstring wstr64 = L"123567890111111";
		EXPECT_TRUE(UNONE::StrToIntegerA(str) == 12356789);
		EXPECT_TRUE(UNONE::StrToIntegerW(wstr) == 12356789);
		EXPECT_FALSE(UNONE::StrToIntegerA(str) == 123567890111111);
		EXPECT_TRUE(UNONE::StrToInteger64A(str) == 12356789);
		EXPECT_TRUE(UNONE::StrToInteger64W(wstr) == 12356789);
		EXPECT_TRUE(UNONE::StrToInteger64A(str64) == 123567890111111);
		EXPECT_TRUE(UNONE::StrToInteger64W(wstr64) == 123567890111111);
	}
}

TEST(TestStrStreamOps, StrTest)
{
	{// UNICODE/ASNI string convert test
		typedef struct _STRING_HIDE {
			USHORT Length;
			USHORT MaximumLength;
			PCHAR  Buffer;
		} STRING_HIDE, *PSTRING_HIDE;
		typedef struct _UNICODE_STRING_HIDE {
			USHORT  Length;
			USHORT  MaximumLength;
			PWSTR  Buffer;
		} UNICODE_STRING_HIDE, *PUNICODE_STRING_HIDE;
		std::string str = "Hello ANSI_STRING";
		std::wstring wstr = L"Hello UNICODE_STRING";
		STRING_HIDE astr = {(USHORT)str.size(), (USHORT)str.capacity(), (PCHAR)str.c_str()};
		UNICODE_STRING_HIDE ustr = {(USHORT)(wstr.size()*2), (USHORT)(wstr.capacity()*2), (PWSTR)wstr.c_str()};
		EXPECT_TRUE(UNONE::StrAstrToStr(&astr) == str);
		EXPECT_TRUE(UNONE::StrUstrToWide(&ustr) == wstr);
	}

	{// stream test
		std::string str = "hello stream world";
		std::wstring wstr = L"hello stream world";
		std::string stream = "68656C6C6F2073747265616D20776F726C64";
		std::string stream_w = "680065006C006C006F002000730074007200650061006D00200077006F0072006C006400";
		EXPECT_TRUE(UNONE::StrStreamToHexStrA(str) == stream);
		EXPECT_TRUE(UNONE::StrHexStrToStreamA(stream) == str);
		EXPECT_TRUE(UNONE::StrStreamToHexStrW(wstr) == stream_w);
		EXPECT_TRUE(UNONE::StrHexStrToStreamW(stream_w) == wstr);
	}
}

TEST(TestStrCharsets, StrTest)
{
	{// string charsets test
		EXPECT_TRUE(UNONE::StrToA(L"Hello,World") == "Hello,World");
		EXPECT_TRUE(UNONE::StrToW("Hello,World") == L"Hello,World");
		EXPECT_TRUE(UNONE::StrWideToACP(L"Hello,World") == "Hello,World");
		EXPECT_TRUE(UNONE::StrWideToUTF8(L"Hello,World") == "Hello,World");
		EXPECT_TRUE(UNONE::StrWideToCode(936, L"你好，世界") == "\xC4\xE3\xBA\xC3\xA3\xAC\xCA\xC0\xBD\xE7");
		EXPECT_TRUE(UNONE::StrWideToCode(950, L"妳好，世界") == "\xA9\x70\xA6\x6E\xA1\x41\xA5\x40\xAC\xC9");
		EXPECT_TRUE(UNONE::StrWideToCode(866, L"Здравствуй,мир") == "\x87\xA4\xE0\xA0\xA2\xE1\xE2\xA2\xE3\xA9\x2C\xAC\xA8\xE0");
		EXPECT_TRUE(UNONE::StrCodeToWide(936, "\xC4\xE3\xBA\xC3\xA3\xAC\xCA\xC0\xBD\xE7") == L"你好，世界");
		EXPECT_TRUE(UNONE::StrCodeToWide(950, "\xA9\x70\xA6\x6E\xA1\x41\xA5\x40\xAC\xC9") == L"妳好，世界");
		EXPECT_TRUE(UNONE::StrCodeToWide(866, "\x87\xA4\xE0\xA0\xA2\xE1\xE2\xA2\xE3\xA9\x2C\xAC\xA8\xE0") == L"Здравствуй,мир");
		EXPECT_TRUE(UNONE::StrCodeToCode(936, 950, "\xA9\x70\xA6\x6E\xA1\x41\xA5\x40\xAC\xC9") == "\x8A\x85\xBA\xC3\xA3\xAC\xCA\xC0\xBD\xE7");
	}
}

TEST(TestStrCmp, StrTest)
{
	{// string compare test
		std::string str = "123ABC";
		std::wstring wstr = L"123ABC";
		EXPECT_TRUE(UNONE::StrCompareIA(str, "123ABC"));
		EXPECT_TRUE(UNONE::StrCompareIW(wstr, L"123ABC"));
		EXPECT_TRUE(UNONE::StrWildCompareA(str, "12*ABC"));
		EXPECT_TRUE(UNONE::StrWildCompareA(str, "1*ABC"));
		EXPECT_TRUE(UNONE::StrWildCompareA(str, "12?ABC"));
		EXPECT_FALSE(UNONE::StrWildCompareA(str, "1?ABC"));
		EXPECT_TRUE(UNONE::StrWildCompareW(wstr, L"123*ABC"));
		EXPECT_TRUE(UNONE::StrWildCompareW(wstr, L"*ABC"));
		EXPECT_TRUE(UNONE::StrWildCompareW(wstr, L"*A*"));
		EXPECT_TRUE(UNONE::StrWildCompareIA(str, "1*aBc"));
		EXPECT_TRUE(UNONE::StrWildCompareIA(str, "12?Abc"));
		EXPECT_TRUE(UNONE::StrWildCompareIW(wstr, L"1*aBc"));
		EXPECT_TRUE(UNONE::StrWildCompareIW(wstr, L"12?Abc"));
		EXPECT_TRUE(UNONE::StrDelimitCompareA("2020.12.12.12", "2019.1200.12.12") > 0);
		EXPECT_TRUE(UNONE::StrDelimitCompareW(L"2020_12_12_12", L"2019_1200_12_12", L"_") > 0);
	}
}

TEST(TestStrFmt, StrTest)
{
	{// string compare test
		std::string str;
		std::wstring wstr;
		UNONE::StrFormatA(str, "hello %s", "unone");
		UNONE::StrFormatW(wstr, L"hello %s", L"unone");
		EXPECT_TRUE(str == "hello unone");
		EXPECT_TRUE(wstr == L"hello unone");
		EXPECT_TRUE(UNONE::StrFormatA("hello %s", "unone") == "hello unone");
		EXPECT_TRUE(UNONE::StrFormatW(L"hello %s", L"unone") == L"hello unone");
	}
}

TEST(TestStrFind, StrTest)
{
	{// string find test
		EXPECT_TRUE(UNONE::StrContainA("hello unone", "unone"));
		EXPECT_FALSE(UNONE::StrContainA("hello unone", "wolrd"));
		EXPECT_TRUE(UNONE::StrContainW(L"hello unone", L"unone"));
		EXPECT_FALSE(UNONE::StrContainW(L"hello unone", L"wolrd"));
		EXPECT_TRUE(UNONE::StrContainIA("hello unone", "UNoNE"));
		EXPECT_TRUE(UNONE::StrContainIW(L"hello unone", L"UNoNE"));
		EXPECT_TRUE(UNONE::StrIndexIA("hello unone", "unOne") != nullptr);
		EXPECT_TRUE(UNONE::StrIndexIA(std::string("hello unone"), std::string("unne")) == std::string::npos);
		EXPECT_TRUE(UNONE::StrIndexIW(L"hello unone", L"unOne") != nullptr);
		EXPECT_TRUE(UNONE::StrIndexIW(std::wstring(L"hello unone"), std::wstring(L"unne")) == std::wstring::npos);
	}
}

TEST(TestStrTrim, StrTest)
{
	{// string trim test
		EXPECT_TRUE(UNONE::StrTrimA("\r\nunone \r\n") == "unone");
		EXPECT_TRUE(UNONE::StrTrimA("\r\nunone ttt","t") == "\r\nunone ");
		EXPECT_TRUE(UNONE::StrTrimW(L"\r\nunone \r\n") == L"unone");
		EXPECT_TRUE(UNONE::StrTrimW(L"\r\nunone ttt",L"t") == L"\r\nunone ");
		EXPECT_TRUE(UNONE::StrTrimLeftA("\r\nunone \r\n") == "unone \r\n");
		EXPECT_TRUE(UNONE::StrTrimLeftW(L"tttunone",L"t") == L"unone");
		EXPECT_TRUE(UNONE::StrTrimRightA("\r\nunone \r\n") == "\r\nunone");
		EXPECT_TRUE(UNONE::StrTrimRightW(L"\r\nunone ttt",L"t") == L"\r\nunone ");
	}
}

TEST(TestStrSplit, StrTest)
{
	{// string trim test
		std::vector<std::string> vec;
		std::vector<std::string> vec_true;
		std::vector<std::wstring> wvec;
		std::vector<std::wstring> wvec_true;
		vec_true.push_back("Hello");
		vec_true.push_back("World");
		wvec_true.push_back(L"Hello");
		wvec_true.push_back(L"World");
		std::string primary = "HelloUNONEWorld";
		std::wstring primary_w = L"HelloUNONEWorld";
		UNONE::StrSplitA(primary, "UNONE", vec);
		UNONE::StrSplitW(primary_w, L"UNONE", wvec);
		EXPECT_TRUE(vec == vec_true);
		EXPECT_TRUE(wvec == wvec_true);
		vec.clear();
		wvec.clear();
		UNONE::StrSplitIA(primary, "unone", vec);
		UNONE::StrSplitIW(primary_w, L"unone", wvec);
		EXPECT_TRUE(vec == vec_true);
		EXPECT_TRUE(wvec == wvec_true);
		primary = "Hello\r\nWorld";
		primary_w = L"Hello\nWorld";
		vec.clear();
		wvec.clear();
		UNONE::StrSplitLinesA(primary, vec);
		UNONE::StrSplitLinesW(primary_w, wvec);
		EXPECT_TRUE(vec == vec_true);
		EXPECT_TRUE(wvec == wvec_true);

		//string truncate test
		EXPECT_TRUE(UNONE::StrTruncateA("AHelloBWorldC", "A", "B") == "Hello");
		EXPECT_TRUE(UNONE::StrTruncateW(L"AHelloBWorldC", L"B", L"C") == L"World");
		EXPECT_TRUE(UNONE::StrTruncateIA("AHelloBWorldC", "a", "b") == "Hello");
		EXPECT_TRUE(UNONE::StrTruncateIW(L"AHelloBWorldC", L"b", L"c") == L"World");
	}
}

TEST(TestStrJoin, StrTest)
{
	{// string join test
		std::vector<std::string> vec_true;
		std::vector<std::wstring> wvec_true;
		vec_true.push_back("Hello");
		vec_true.push_back("World");
		wvec_true.push_back(L"Hello");
		wvec_true.push_back(L"World");
		EXPECT_TRUE(UNONE::StrJoinA(vec_true) == "HelloWorld");
		EXPECT_TRUE(UNONE::StrJoinA(vec_true, " ") == "Hello World");
		EXPECT_TRUE(UNONE::StrJoinW(wvec_true) == L"HelloWorld");
		EXPECT_TRUE(UNONE::StrJoinW(wvec_true, L" ") == L"Hello World");
	}
}

TEST(TestStrInsert, StrTest)
{
	{// string insert test
		std::string hexstr = "001122AABBCC";
		hexstr = UNONE::StrInsertA(hexstr, 2, "\\x");
		hexstr.insert(0, "\\x");
		EXPECT_TRUE(hexstr == "\\x00\\x11\\x22\\xAA\\xBB\\xCC");

		std::wstring hexstr_w = L"001122AABBCC";
		hexstr_w = UNONE::StrInsertW(hexstr_w, 2, L"\\x");
		hexstr_w.insert(0, L"\\x");
		EXPECT_TRUE(hexstr_w == L"\\x00\\x11\\x22\\xAA\\xBB\\xCC");
	}
}

TEST(TestStrReverse, StrTest)
{
	{// string insert test
		std::string hexstr = "001122AABBCC";
		EXPECT_TRUE(UNONE::StrReverseA(hexstr, 4) == "1100AA22CCBB");
		EXPECT_TRUE(UNONE::StrReverseA(hexstr, 8) == "AA221100CCBB");

		std::wstring hexstr_w = L"001122AABBCC";
		EXPECT_TRUE(UNONE::StrReverseW(hexstr_w, 4) == L"1100AA22CCBB");
		EXPECT_TRUE(UNONE::StrReverseW(hexstr_w, 8) == L"AA221100CCBB");
	}
}

TEST(TestStrRepeat, StrTest)
{
	{// string repeat test
		EXPECT_TRUE(UNONE::StrRepeatA("Go", 3) == "GoGoGo");
		EXPECT_TRUE(UNONE::StrRepeatW(L"Go", 3) == L"GoGoGo");
	}
}

TEST(TestStrReplace, StrTest)
{
	{// string replace test
		std::string str = "Hello World";
		UNONE::StrReplaceA(str, "World", "unone");
		EXPECT_TRUE(str == "Hello unone");
		str = "Hello World";
		UNONE::StrReplaceIA(str, "WORLD", "unone");
		EXPECT_TRUE(str == "Hello unone");

		std::wstring wstr = L"Hello World";
		UNONE::StrReplaceW(wstr, L"World", L"unone");
		EXPECT_TRUE(wstr == L"Hello unone");
		wstr = L"Hello World";
		UNONE::StrReplaceIW(wstr, L"WORLD", L"unone");
		EXPECT_TRUE(wstr == L"Hello unone");
	}
}
