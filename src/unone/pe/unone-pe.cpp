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
#include <common/unone-common.h>
#include <native/unone-native.h>
#include <internal/unone-internal.h>
#include <string/unone-str.h>
#include <memory/unone-mm.h>
#include "unone-pe.h"

namespace UNONE {

#define RVA_REBASE(rva) (base_type == UNONE::BASE_FILE ? UNONE::PeRvaToRaw(base, rva) : rva)

/*++
Description:
	map image by file buffer
Arguments:
	file_buf - file buffer
	file_size - file size
Return:
	image base
--*/
CHAR* PeMapImage(__in CHAR *file_buf, __in DWORD file_size)
{
	// check 1
	if (!file_buf || !file_size || !PeValid(file_buf))
		return NULL;

	DWORD hdr_size = 0;
	DWORD image_size = 0;
	PIMAGE_SECTION_HEADER section;
	PIMAGE_DOS_HEADER dos_hdr = PE_DOS_HEADER(file_buf);
	PIMAGE_NT_HEADERS nt_hdr = PE_NT_HEADER(file_buf);
	DWORD section_cnt = nt_hdr->FileHeader.NumberOfSections;

	if (PE_X64(file_buf)) {
		image_size = PE_OPT_HEADER64(file_buf)->SizeOfImage;
		hdr_size = (DWORD)dos_hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (section_cnt * sizeof(IMAGE_SECTION_HEADER));
	}	else {
		image_size = PE_OPT_HEADER32(file_buf)->SizeOfImage;
		hdr_size = (DWORD)dos_hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (section_cnt * sizeof(IMAGE_SECTION_HEADER));
	}

	DWORD checked_vsize = 0;
	DWORD checked_rsize = 0;
	section = IMAGE_FIRST_SECTION(nt_hdr);
	for (DWORD i = 0; i < section_cnt; i++) {
		DWORD vs1 = section->Misc.VirtualSize;
		DWORD vs2 = section->SizeOfRawData;
		checked_vsize = MAX(checked_vsize, section->VirtualAddress + MAX(vs1, vs2));
		checked_rsize = MAX(checked_rsize, section->PointerToRawData + section->SizeOfRawData);
		section++;
	}
	// check 2
	if (file_size < checked_rsize || image_size < checked_vsize) {
		return NULL;
	}

	CHAR* image = (CHAR*)VirtualAlloc(NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!image) {
		UNONE_ERROR("VirtualAlloc err:%d", GetLastError());
		return NULL;
	}
	RtlZeroMemory(image, image_size);
	RtlCopyMemory(image, file_buf, hdr_size);
	section = IMAGE_FIRST_SECTION(nt_hdr);
	for (DWORD i = 0; i < section_cnt; i++) {
		DWORD va = section->VirtualAddress;
		DWORD raw = section->PointerToRawData;
		DWORD raw_size = section->SizeOfRawData;
		RtlCopyMemory(image + va, file_buf + raw, raw_size);
		section++;
	}
	return image;
}

/*++
Description:
	map image by file path
Arguments:
	path - file path
Return:
	image base
--*/
CHAR* PeMapImageByPathA(__in const std::string &path)
{
	return PeMapImageByPathW(StrToW(path));
}

/*++
Description:
	map image by file path
Arguments:
	path - file path
Return:
	image base
--*/
CHAR* PeMapImageByPathW(__in const std::wstring &path)
{
	DWORD file_size = 0;
	HANDLE fd, hmap;
	CHAR* file_buf = MmMapFileW(path, file_size, fd, hmap);
	if (!file_buf) return NULL;
	CHAR* image = PeMapImage(file_buf, file_size);
	MmUnmapFile(file_buf, fd, hmap);
	return image;
}

/*++
Description:
	unmap image
Arguments:
	base - image base
Return:
	BOOL
--*/
bool PeUnmapImage(__in CHAR *base)
{
	if (!base) return FALSE;
	return VirtualFree(base, 0, MEM_RELEASE) == TRUE;
}

/*++
Description:
	rva to raw
Arguments:
	base - image/file base
	rva = rva address
Return:
	raw
--*/
DWORD PeRvaToRaw(__in CHAR *base, __in DWORD rva)
{
	PIMAGE_NT_HEADERS nt_hdr = PE_NT_HEADER(base);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_hdr);
	for (DWORD i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++) {
		DWORD va_base = section->VirtualAddress;
		DWORD raw_base = section->PointerToRawData;
		DWORD raw_size = section->SizeOfRawData;
		if (IN_RANGE(rva, va_base, raw_size))
			return raw_base + (rva - va_base);
		section++;
	}
	return 0;
}

/*++
Description:
	raw to rva
Arguments:
	base - image/file base
	raw = raw address
Return:
	rva
--*/
DWORD PeRawToRva(__in CHAR *base, __in DWORD raw)
{
	PIMAGE_NT_HEADERS nt_hdr = PE_NT_HEADER(base);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_hdr);
	for (DWORD i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++) {
		DWORD va_base = section->VirtualAddress;
		DWORD raw_base = section->PointerToRawData;
		DWORD raw_size = section->SizeOfRawData;
		if (IN_RANGE(raw, raw_base, raw_size))
			return va_base + (raw - raw_base);
		section++;
	}
	return 0;
}

/*++
Description:
	check pe is valid
Arguments:
	base - image/file base
Return:
	BOOL
--*/
bool PeValid(__in CHAR *base)
{
	__try {
		PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)base;
		PIMAGE_NT_HEADERS nt_hdr = NULL;
		if (dos_hdr == NULL)
			return false;
		if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE)
			return false;
		nt_hdr = (PIMAGE_NT_HEADERS)(base + dos_hdr->e_lfanew);
		if (nt_hdr->Signature != IMAGE_NT_SIGNATURE)
			return false;
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

/*++
Description:
	check region is valid
Arguments:
	base - image base
	va - virtual address
	size - region size
Return:
	BOOL
--*/
bool PeRegionValid(CHAR *base, PVOID va, DWORD size /*= 0*/)
{
	DWORD image_size = PeGetImageSize(base);
	return (IN_RANGE((CHAR*)va, base, image_size)) && (IN_RANGE((CHAR*)va + size, base, image_size));
}

/*++
Description:
	check pe is x64
Arguments:
	base - image/file base
Return:
	BOOL
--*/
bool PeX64(__in CHAR *base)
{
	return PE_OPT_HEADER(base)->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

/*++
Description:
	get time stamp
Arguments:
	base - image/file base
Return:
	time stamp
--*/
DWORD PeGetTimeStamp(__in CHAR *base)
{
	if (!PeValid(base)) return 0;
	return PE_NT_HEADER(base)->FileHeader.TimeDateStamp;
}

/*++
Description:
	get entry point
Arguments:
	base - image/file base
Return:
	image size
--*/
DWORD PeGetImageSize(__in CHAR *base)
{
	if (!PeValid(base)) return 0;
	if (PE_X64(base))
		return PE_OPT_HEADER64(base)->SizeOfImage;
	else
		return PE_OPT_HEADER32(base)->SizeOfImage;
}

/*++
Description:
	get entry point
Arguments:
	base - image/file base
Return:
	entry point
--*/
DWORD PeGetEntryPoint(__in CHAR *base)
{
	if (!PeValid(base)) return 0;
	if (PE_X64(base))
		return PE_OPT_HEADER64(base)->AddressOfEntryPoint;
	else
		return PE_OPT_HEADER32(base)->AddressOfEntryPoint;
}

/*++
Description:
	get directory by index
Arguments:
	idx - directory index, IMAGE_DIRECTORY_ENTRY_EXPORT/IMAGE_DIRECTORY_ENTRY_IMPORT...
	base - image/file base
	base_type = implies image or file
Return:
	directory
--*/
PIMAGE_DATA_DIRECTORY PeGetDataDirectory(__in DWORD idx, __in CHAR *base, __in UNONE::PE_BASE_TYPE base_type /*= BASE_IMAGE*/)
{
	if (!PeValid(base)) return NULL;
	DWORD rva = 0;
	DWORD size = 0;
	if (PE_X64(base)) {
		return &PE_OPT_HEADER64(base)->DataDirectory[idx];
	} else {
		return &PE_OPT_HEADER32(base)->DataDirectory[idx];
	}
}

/*++
Description:
	get entity by index
Arguments:
	idx - directory index, IMAGE_DIRECTORY_ENTRY_EXPORT/IMAGE_DIRECTORY_ENTRY_IMPORT...
	base - image/file base
	base_type = implies image or file
Return:
	entity
--*/
CHAR* PeGetDataEntity(__in DWORD idx, __in CHAR *base, __in UNONE::PE_BASE_TYPE base_type /*= BASE_IMAGE*/)
{
	PIMAGE_DATA_DIRECTORY dir = PeGetDataDirectory(idx, base, base_type);
	if (!dir) return NULL;

	CHAR* va = base;
	DWORD rva = dir->VirtualAddress;
	DWORD size = dir->Size;
	if (!rva || !size) return NULL;

	va = base + rva;
	if (base_type == UNONE::BASE_FILE) {
		va = base + PeRvaToRaw(base, rva);
	}
	if (!PeRegionValid(base, va, size)) return NULL;
	return va;
}

/*++
Description:
	get entity by index
Arguments:
	idx - directory index, IMAGE_DIRECTORY_ENTRY_EXPORT/IMAGE_DIRECTORY_ENTRY_IMPORT...
	base - image/file base
	base_type = implies image or file
Return:
	entity
--*/
CHAR* PeGetDataEntityByDir(__in PIMAGE_DATA_DIRECTORY dir, __in CHAR *base, __in UNONE::PE_BASE_TYPE base_type /*= BASE_IMAGE*/)
{
	if (!dir) return NULL;

	CHAR* va = base;
	DWORD rva = dir->VirtualAddress;
	DWORD size = dir->Size;
	if (!rva || !size) return NULL;

	va = base + RVA_REBASE(rva);
	if (!PeRegionValid(base, va, size)) return NULL;
	return va;
}

/*++
Description:
	get pdb file
Arguments:
	base - image/file base
	base_type = implies image or file
Return:
	entity
--*/
std::string PeGetPdb(__in CHAR *base, __in UNONE::PE_BASE_TYPE base_type /*= BASE_IMAGE*/)
{
	PIMAGE_DEBUG_DIRECTORY dbg = (PIMAGE_DEBUG_DIRECTORY)
		PeGetDataEntity(IMAGE_DIRECTORY_ENTRY_DEBUG, base, base_type);
	if (dbg == NULL || dbg->Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
		!dbg->AddressOfRawData || !dbg->SizeOfData) {
		return "";
	}
	DWORD offset = dbg->AddressOfRawData;
	if (base_type == BASE_FILE) offset = PeRvaToRaw(base, offset);
	CV_HEADER* cv_hdr = (CV_HEADER*)(base + offset);
	DWORD cv_size = dbg->SizeOfData;
	if (!PeRegionValid(base, cv_hdr, cv_size))
		return "";
	std::string pdb;
	CHAR* name = NULL;
	DWORD name_size = 0;
	if (cv_hdr->Signature == NB10_SIG) {
		name = (CHAR*)((CV_INFO_PDB20*)cv_hdr)->PdbFileName;
		name_size = (DWORD)strlen(name);
		if (!name_size || name_size >= MAX_PATH)
			return "";
		pdb = name;
	}	else if (cv_hdr->Signature == RSDS_SIG) {
		name = (CHAR*)((CV_INFO_PDB70*)cv_hdr)->PdbFileName;
		name_size = (DWORD)strlen(name);
		if (!name_size || name_size >= MAX_PATH)
			return "";
		pdb = StrUTF8ToACP(name);
	}
	return pdb;
}

/*++
Description:
	get pdb file
Arguments:
	base - image/file base
	base_type = implies image or file
Return:
	entity
--*/
std::string PeGetPdbByFile(__in std::wstring path)
{
	DWORD file_size = 0;
	HANDLE fd, hmap;
	CHAR* file_buf = MmMapFileW(path, file_size, fd, hmap);
	if (!file_buf) return NULL;
	std::string pdb_file = PeGetPdb(file_buf, UNONE::BASE_FILE);
	MmUnmapFile(file_buf, fd, hmap);
	return pdb_file;
}

/*++
Description:
	get function address, analogous GetProcAddress
Arguments:
	base - image/file base
	proc_name - function name
	base_type = implies image or file
Return:
	function address
--*/
PVOID PeGetProcAddress(CHAR *base, CHAR* proc_name, __in UNONE::PE_BASE_TYPE base_type /*= BASE_IMAGE*/)
{
	PVOID func_addr = NULL;

	PIMAGE_DATA_DIRECTORY dir = PeGetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT, base, base_type);
	if (!dir) return NULL;

	PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)PeGetDataEntityByDir(dir, base, base_type);
	if (!export_dir) return NULL;

	PDWORD addr_names = (PDWORD)(RVA_REBASE(export_dir->AddressOfNames) + base);
	PDWORD addr_funcs = (PDWORD)(RVA_REBASE(export_dir->AddressOfFunctions) + base);
	PWORD addr_ordinals = (PWORD)(RVA_REBASE(export_dir->AddressOfNameOrdinals) + base);
	DWORD cnt_names = export_dir->NumberOfNames;
	DWORD cnt_ordinals = export_dir->NumberOfFunctions;
	DWORD base_ordinal = export_dir->Base;

	if ((ULONG_PTR)proc_name & (ULONG_PTR)(~0xFFFF)) { // names
		for (DWORD i = 0; i < cnt_names; i++) {
			CHAR* func_name = base + RVA_REBASE(addr_names[i]);
			if (!_stricmp(func_name, proc_name)) {
				DWORD idx = addr_ordinals[i];
				if (idx >= cnt_ordinals) return NULL;
				func_addr = RVA_REBASE(addr_funcs[idx]) + base;
				break;
			}
		}
	} else { // ordinal
		DWORD ordinal = (DWORD)proc_name;
		if (ordinal < base_ordinal || ordinal >= (base_ordinal + cnt_ordinals))
			return NULL;
		func_addr = RVA_REBASE(addr_funcs[ordinal - base_ordinal]) + base;
	}
	if (IN_RANGE(func_addr, export_dir, dir->Size)) { // dll forwards
		size_t tmp_size = strlen((CHAR*)func_addr) + 1;
		CHAR* buf = (CHAR*)malloc(tmp_size);
		memset(buf, 0, tmp_size);
		strcpy_s(buf, tmp_size, (CHAR*)func_addr);
		CHAR* sep = strchr(buf, '.');
		if (!sep) {
			free(buf);
			return NULL;
		}
		*sep = '\0';
		func_addr = PeGetProcAddress((CHAR*)GetModuleHandleA(buf), sep + 1, UNONE::BASE_IMAGE);
		free(buf);
	} else {
		if (!PeRegionValid(base, func_addr)) return NULL;
	}
	return func_addr;
}

PIMAGE_THUNK_DATA PeGetImportThunkData(CHAR* base, CHAR* dll_name, CHAR* func_name, __in UNONE::PE_BASE_TYPE base_type)
{
	if (!base || !dll_name || !func_name)
		return NULL;

	PIMAGE_THUNK_DATA found_thunk = NULL;
	BOOL is_ordinal = FALSE;

	PIMAGE_IMPORT_DESCRIPTOR imp_desc = (PIMAGE_IMPORT_DESCRIPTOR) 
		PeGetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT, base, base_type);
	if (imp_desc == NULL) return NULL;

	if (((ULONG_PTR)func_name & (ULONG_PTR)(~0xFFFF)) == 0)
		is_ordinal = TRUE;

	while (imp_desc->Name != 0) {
		char* imp_dll = base + imp_desc->Name;
		if (_stricmp(dll_name, imp_dll)) {
			PIMAGE_THUNK_DATA o_thunk = (PIMAGE_THUNK_DATA)(base + imp_desc->OriginalFirstThunk);
			PIMAGE_THUNK_DATA f_thunk = (PIMAGE_THUNK_DATA)(base + imp_desc->FirstThunk);
			if (o_thunk == NULL) o_thunk = f_thunk;
			while (o_thunk != NULL && o_thunk->u1.Ordinal != 0) {
				if (is_ordinal) {
					if (IMAGE_SNAP_BY_ORDINAL(o_thunk->u1.Ordinal)) {
						if (((ULONG_PTR)func_name & (ULONG_PTR)(0xFFFF)) == (o_thunk->u1.Ordinal&(~IMAGE_ORDINAL_FLAG))) {
							found_thunk = (PIMAGE_THUNK_DATA)f_thunk;
							break;
						}
					}
				} else {
					if (!IMAGE_SNAP_BY_ORDINAL(o_thunk->u1.Ordinal)) {
						PIMAGE_IMPORT_BY_NAME imp_func = (PIMAGE_IMPORT_BY_NAME)(base + o_thunk->u1.AddressOfData);
						if (_stricmp(func_name, (LPCSTR)(imp_func->Name))) {
							found_thunk = (PIMAGE_THUNK_DATA)f_thunk;
							break;
						}
					}
				}
				f_thunk++;
				o_thunk++;
			}
		}
		imp_desc++;
	}
	return found_thunk;
}

} // namespace UNONE