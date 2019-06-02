#pragma once
#include "gtest.h"
#include "../../Common/common.h"

#ifdef _M_IX86

//32λ
#ifdef _DEBUG
#ifdef _DLL
#pragma comment(lib, "lib/gtest32-MDd.lib")
#else
#pragma comment(lib, "lib/gtest32-MTd.lib")
#endif //_DLL
#else
#ifdef _DLL
#pragma comment(lib, "lib/gtest32-MD.lib")
#else
#pragma comment(lib, "lib/gtest32-MT.lib")
#endif //_DLL
#endif //_DEBUG

#else

//64λ
#ifdef _DEBUG
#ifdef _DLL
#pragma comment(lib, "lib/gtest64-MDd.lib")
#else
#pragma comment(lib, "lib/gtest64-MTd.lib")
#endif //_DLL
#else
#ifdef _DLL
#pragma comment(lib, "lib/gtest64-MD.lib")
#else
#pragma comment(lib, "lib/gtest64-MT.lib")
#endif //_DLL
#endif //_DEBUG

#endif //_M_IX86
