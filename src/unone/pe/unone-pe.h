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
#include "elf/elf.h"
#include "elf/elf-parser.h"

namespace UNONE {

#ifdef _UNICODE
#define PeMapImageByPath PeMapImageByPathW
#else
#define PeMapImageByPath PeMapImageByPathA
#endif // _UNICODE

enum PE_BASE_TYPE {
	BASE_UNKNOWN = 0,
	BASE_FILE = 1,
	BASE_IMAGE = 2,
};

#define NB10_SIG	'01BN'
#define RSDS_SIG	'SDSR'
struct CV_HEADER {
	DWORD Signature;
	DWORD Offset;
};
struct CV_INFO_PDB20 {
	CV_HEADER	CvHeader;
	DWORD		Signature;
	DWORD		Age;
	BYTE		PdbFileName[1];
};
struct CV_INFO_PDB70 {
	DWORD	CvSignature;
	GUID	Signature;
	DWORD	Age;
	BYTE	PdbFileName[1];
};

#define PE_DOS_HEADER(base) ((PIMAGE_DOS_HEADER)base)
#define PE_NT_HEADER(base) ((PIMAGE_NT_HEADERS)((CHAR*)base + PE_DOS_HEADER(base)->e_lfanew))
#define PE_OPT_HEADER(base) ((PIMAGE_OPTIONAL_HEADER)(&PE_NT_HEADER(base)->OptionalHeader))
#define PE_OPT_HEADER32(base) ((PIMAGE_OPTIONAL_HEADER32)(&PE_NT_HEADER(base)->OptionalHeader))
#define PE_OPT_HEADER64(base) ((PIMAGE_OPTIONAL_HEADER64)(&PE_NT_HEADER(base)->OptionalHeader))
#define PE_X64(base) (PE_OPT_HEADER(base)->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

UNONE_API CHAR* PeMapImage(__in CHAR *file_buf, __in DWORD file_size);
UNONE_API CHAR* PeMapImageByPathA(__in const std::string &path);
UNONE_API CHAR* PeMapImageByPathW(__in const std::wstring &path);
UNONE_API bool PeUnmapImage(__in CHAR *base);
UNONE_API DWORD PeRvaToRaw(__in CHAR *base, __in DWORD rva);
UNONE_API DWORD PeRawToRva(__in CHAR *base, __in DWORD raw);
UNONE_API bool PeValid(__in CHAR *base);
UNONE_API bool PeRegionValid(CHAR *base, PVOID va, DWORD size = 0);
UNONE_API bool PeX64(__in CHAR *base);
UNONE_API DWORD PeGetTimeStamp(__in CHAR *base);
UNONE_API DWORD PeGetImageSize(__in CHAR *base);
UNONE_API DWORD PeGetEntryPoint(__in CHAR *base);
UNONE_API PIMAGE_DATA_DIRECTORY PeGetDataDirectory(__in DWORD idx, __in CHAR *base, __in UNONE::PE_BASE_TYPE base_type = BASE_IMAGE);
UNONE_API CHAR* PeGetDataEntity(__in DWORD idx, __in CHAR *base, __in UNONE::PE_BASE_TYPE base_type = BASE_IMAGE);
UNONE_API CHAR* PeGetDataEntityByDir(__in PIMAGE_DATA_DIRECTORY dir, __in CHAR *base, __in UNONE::PE_BASE_TYPE base_type = BASE_IMAGE);
UNONE_API std::string PeGetPdb(__in CHAR *base, __in UNONE::PE_BASE_TYPE base_type = BASE_IMAGE);
UNONE_API std::string PeGetPdbByFile(__in std::wstring path);
UNONE_API PVOID PeGetProcAddress(CHAR *base, CHAR* proc_name, __in UNONE::PE_BASE_TYPE base_type = BASE_IMAGE);
UNONE_API std::string PeGetProcNameByOrdinal(CHAR* base, DWORD ordinal, __in UNONE::PE_BASE_TYPE base_type = BASE_IMAGE);

} // namespace UNONE
