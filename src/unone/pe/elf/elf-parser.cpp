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
#include <string>
#include <internal/unone-internal.h>
#include <string/unone-str.h>
#include "elf-parser.h"
#include "elf.h"
namespace UNONE {

/*++
Description:
	check elf is x64
Arguments:
	base - image/file base
Return:
	BOOL
--*/
bool ElfX64(__in CHAR* base)
{
	UCHAR* e_ident = ELF_HEADER32(base)->e_ident;
	return e_ident[4] == ELFCLASS64;
}

/*++
Description:
	check elf is valid
Arguments:
	base - image/file base
Return:
	BOOL
--*/
bool ElfValid(__in CHAR* base)
{
	__try {
		UCHAR* e_ident = ELF_HEADER32(base)->e_ident;
		return memcmp(e_ident, ELFMAG, sizeof(ELFMAG)-1) == 0;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}
/*++
Description:
	get entry point
Arguments:
	base - image/file base
Return:
	entry point
--*/
uint64_t ElfGetEntryPoint(__in CHAR* base)
{
	if (!ElfValid(base)) return 0;
	if (ELF_X64(base))
		return ELF_HEADER64(base)->e_entry;
	else
		return ELF_HEADER32(base)->e_entry;
}

uint16_t ElfGetPHeaderNums(__in CHAR* base)
{
	if (ELF_X64(base))
		return ELF_HEADER64(base)->e_phnum;
	else
		return ELF_HEADER32(base)->e_phnum;
}

uint16_t ElfGetSectionHeaderNums(__in CHAR* base)
{
	if (ELF_X64(base))
		return ELF_HEADER64(base)->e_shnum;
	else
		return ELF_HEADER32(base)->e_shnum;
}

std::string ElfGetEHeaderTypeString(uint16_t type)
{
	switch (type) {
	case ET_EXEC:
		return "[ET_EXEC] Executable";
	case ET_REL:
		return "[ET_REL] Relocatable";
	case ET_DYN:
		return "[ET_DYN] Shared object";
	case ET_CORE:
		return "[ET_CORE] Core";
	default:
		return "Unknown";
	}
}

std::string ElfGetEHeaderMachineString(uint16_t machine)
{
	switch (machine) {
	case EM_M32:
		return "AT&T WE 32100";
	case EM_SPARC:
		return "Sun Microsystems SPARC";
	case EM_386:
		return "X86";
	case EM_68K:
		return "Motorola 68000";
	case EM_88K:
		return "Motorola 88000";
	case EM_860:
		return "Intel 80860";
	case EM_MIPS:
		return "MIPS RS3000 (big-endian only)";
	case EM_PARISC:
		return "HP/PA";
	case EM_SPARC32PLUS:
		return "SPARC with enhanced instruction set";
	case EM_PPC:
		return "PowerPC";
	case EM_PPC64:
		return "PowerPC 64-bit";
	case EM_S390:
		return "IBM S/390";
	case EM_ARM:
		return "ARM32";
	case EM_AARCH64:
		return "ARM64";
	case EM_SH:
		return "Renesas SuperH";
	case EM_SPARCV9:
		return "SPARC v9 64-bit";
	case EM_IA_64:
		return "Intel Itanium";
	case EM_X86_64:
		return "X64";
	case EM_VAX:
		return "DEC Vax";
	default:
		return "Unknown";
	}
}

std::string ElfGetPHeaderTypeString(uint32_t type)
{
	switch (type) {
	case PT_NULL:
		return "NULL";
	case PT_LOAD:
		return "LOAD";
	case PT_DYNAMIC:
		return "DYNAMIC";
	case PT_INTERP:
		return "INTERP";
	case PT_NOTE:
		return "NOTE";
	case PT_SHLIB:
		return "SHLIB";
	case PT_PHDR:
		return "PHDR";
	case PT_TLS:
		return "TLS";
	case PT_NUM:
		return "NUM";
	case PT_LOOS:
		return "LOOS";
	case PT_GNU_EH_FRAME:
		return "GNU_EH_FRAME";
	case PT_GNU_STACK:
		return "GNU_STACK";
	case PT_GNU_RELRO:
		return "GNU_RELRO";
	case PT_LOSUNW:
		return "LOSUNW";
	case PT_SUNWSTACK:
		return "SUNWSTACK";
	case PT_HIOS:
		return "HIOS";
	case PT_LOPROC:
		return "LOPROC";
	case PT_HIPROC:
		return "HIPROC";
	default:
		return "UNKNWON";
	}
}

std::string ElfGetPHeaderFlagString(uint32_t flags)
{
	char perm[4] = { 0 };

	if (flags & PF_R)
		perm[0] = 'R';
	else
		perm[0] = '-';

	if (flags & PF_W)
		perm[1] = 'W';
	else
		perm[1] = '-';

	if (flags & PF_X)
		perm[2] = 'X';
	else
		perm[2] = '-';

	return perm;
}

std::string ElfGetSectionName(CHAR* base, uint32_t offset)
{
	CHAR* strtab;
	if (ELF_X64(base)) {
		strtab = base + ELF_SH_STRTAB64(base);
	} else {
		strtab = base + ELF_SH_STRTAB32(base);
	}
	return strtab += offset;
}

std::string ElfGetSectionTypeString(uint32_t type)
{
	switch (type) {
	case SHT_NULL:
		return "NULL";
	case SHT_PROGBITS:
		return "PROGBITS";
	case SHT_SYMTAB:
		return "SYMTAB";
	case SHT_STRTAB:
		return "STRTAB";
	case SHT_RELA:
		return "RELA";
	case SHT_HASH:
		return "HASH";
	case SHT_DYNAMIC:
		return "DYNAMIC";
	case SHT_NOTE:
		return "NOTE";
	case SHT_NOBITS:
		return "NOBITS";
	case SHT_REL:
		return "REL";
	case SHT_SHLIB:
		return "SHLIB";
	case SHT_DYNSYM:
		return "DYNSYM";
	case SHT_INIT_ARRAY:
		return "INIT_ARRAY";
	case SHT_FINI_ARRAY:
		return "FINI_ARRAY";
	case SHT_PREINIT_ARRAY:
		return "PREINIT_ARRAY";
	case SHT_GROUP:
		return "GROUP";
	case SHT_SYMTAB_SHNDX:
		return "SYMTAB_SHNDX";
	case SHT_NUM:
		return "NUM";
	case PT_LOOS:
		return "LOOS";
	case SHT_GNU_ATTRIBUTES:
		return "SHT_GNU_ATTRIBUTES";
	case SHT_GNU_HASH:
		return "GNU_HASH";
	case SHT_GNU_LIBLIST:
		return "GNU_LIBLIST";
	case SHT_CHECKSUM:
		return "CHECKSUM";
	case SHT_SUNW_move:
		return "MOVE";
	case SHT_SUNW_COMDAT:
		return "COMDAT";
	case SHT_SUNW_syminfo:
		return "SYMINFO";
	case SHT_GNU_verdef:
		return "VERDEF";
	case SHT_GNU_verneed:
		return "VERNEED";
	case SHT_GNU_versym:
		return "VERSYM";
	case SHT_LOPROC:
		return "LOPROC";
	case SHT_HIPROC:
		return "HIPROC";
	case SHT_LOUSER:
		return "LOUSER";
	case SHT_HIUSER:
		return "HIUSER";
	default:
		return "UNKNOWN";
	}
}

std::string ElfGetSectionFlagString(uint32_t flags)
{
	std::string perm;
	if (flags & SHF_EXCLUDE) perm.insert(perm.begin(), 'E');
	if (flags & SHF_COMPRESSED) perm.insert(perm.begin(), 'C');
	if (flags & SHF_TLS) perm.insert(perm.begin(), 'T');
	if (flags & SHF_GROUP) perm.insert(perm.begin(), 'G');
	if (flags & SHF_OS_NONCONFORMING) perm.insert(perm.begin(), 'O');
	if (flags & SHF_LINK_ORDER) perm.insert(perm.begin(), 'L');
	if (flags & SHF_INFO_LINK) perm.insert(perm.begin(), 'I');
	if (flags & SHF_STRINGS) perm.insert(perm.begin(), 'S');
	if (flags & SHF_MERGE) perm.insert(perm.begin(), 'M');
	if (flags & SHF_EXECINSTR) perm.insert(perm.begin(), 'X');
	if (flags & SHF_ALLOC) perm.insert(perm.begin(), 'A');
	if (flags & SHF_WRITE) perm.insert(perm.begin(), 'W');
	return perm;
}

std::string ElfGetDynamicTypeString(uint32_t tag)
{
	switch (tag) {
	case DT_NULL:
		return "NULL";
	case DT_NEEDED:
		return "NEEDED";
	case DT_PLTRELSZ:
		return "PLTRELSZ";
	case DT_PLTGOT:
		return "PLTGOT";
	case DT_HASH:
		return "HASH";
	case DT_STRTAB:
		return "STRTAB";
	case DT_SYMTAB:
		return "SYMTAB";
	case DT_RELA:
		return "RELA";
	case DT_RELASZ:
		return "RELASZ";
	case DT_RELAENT:
		return "RELAENT";
	case DT_STRSZ:
		return "STRSZ";
	case DT_SYMENT:
		return "SYMENT";
	case DT_INIT:
		return "INIT";
	case DT_FINI:
		return "FINI";
	case DT_SONAME:
		return "SONAME";
	case DT_RPATH:
		return "RPATH";
	case DT_SYMBOLIC:
		return "SYMBOLIC";
	case DT_REL:
		return "REL";
	case DT_RELSZ:
		return "RELSZ";
	case DT_RELENT:
		return "RELENT";
	case DT_PLTREL:
		return "PLTREL";
	case DT_DEBUG:
		return "DEBUG";
	case DT_TEXTREL:
		return "TEXTREL";
	case DT_JMPREL:
		return "JMPREL";
	case DT_BIND_NOW:
		return "BIND_NOW";
	case DT_INIT_ARRAY:
		return "INIT_ARRAY";
	case DT_FINI_ARRAY:
		return "FINI_ARRAY";
	case DT_INIT_ARRAYSZ:
		return "INIT_ARRAYSZ";
	case DT_FINI_ARRAYSZ:
		return "FINI_ARRAYSZ";
	case DT_RUNPATH:
		return "RUNPATH";
	case DT_FLAGS:
		return "FLAGS";
	case DT_PREINIT_ARRAY:
		return "PREINIT_ARRAY";
	case DT_PREINIT_ARRAYSZ:
		return "PREINIT_ARRAYSZ";
	case DT_NUM:
		return "NUM";
	case DT_LOOS:
		return "LOOS";
	case DT_HIOS:
		return "HIOS";
	case DT_LOPROC:
		return "LOPROC";
	case DT_HIPROC:
		return "HIPROC";
	case DT_VALRNGLO:
		return "VALRNGLO";
	case DT_GNU_PRELINKED:
		return "GNU_PRELINKED";
	case DT_GNU_CONFLICTSZ:
		return "GNU_CONFLICTSZ";
	case DT_GNU_LIBLISTSZ:
		return "GNU_LIBLISTSZ";
	case DT_CHECKSUM:
		return "CHECKSUM";
	case DT_PLTPADSZ:
		return "PLTPADSZ";
	case DT_MOVEENT:
		return "MOVEENT";
	case DT_MOVESZ:
		return "MOVESZ";
	case DT_FEATURE_1:
		return "FEATURE_1";
	case DT_POSFLAG_1:
		return "POSFLAG_1";
	case DT_SYMINSZ:
		return "SYMINSZ";
	case DT_SYMINENT:
		return "SYMINENT";
	case DT_ADDRRNGLO:
		return "ADDRRNGLO";
	case DT_GNU_HASH:
		return "GNU_HASH";
	case DT_TLSDESC_PLT:
		return "TLSDESC_PLT";
	case DT_TLSDESC_GOT:
		return "TLSDESC_GOT";
	case DT_GNU_CONFLICT:
		return "GNU_CONFLICT";
	case DT_GNU_LIBLIST:
		return "GNU_LIBLIST";
	case DT_CONFIG:
		return "CONFIG";
	case DT_DEPAUDIT:
		return "DEPAUDIT";
	case DT_AUDIT:
		return "AUDIT";
	case DT_PLTPAD:
		return "PLTPAD";
	case DT_MOVETAB:
		return "MOVETAB";
	case DT_SYMINFO:
		return "SYMINFO";
	case DT_VERSYM:
		return "VERSYM";
	case DT_RELACOUNT:
		return "RELACOUNT";
	case DT_RELCOUNT:
		return "RELCOUNT";
	case DT_FLAGS_1:
		return "FLAGS_1";
	case DT_VERDEF:
		return "VERDEF";
	case DT_VERDEFNUM:
		return "VERDEFNUM";
	case DT_VERNEED:
		return "VERNEED";
	case DT_VERNEEDNUM:
		return "VERNEEDNUM";
	case DT_AUXILIARY:
		return "AUXILIARY";
	}
	return "";
}

std::string ElfGetDynamicFlagString(uint32_t flag)
{
	std::string str;
	if (flag & DF_ORIGIN) str += "ORIGIN ";
	if (flag & DF_SYMBOLIC) str += "SYMBOLIC ";
	if (flag & DF_TEXTREL) str += "TEXTREL ";
	if (flag & DF_BIND_NOW) str += "BIND_NOW ";
	return str;
}

std::string ElfGetSymbolTypeString(uint8_t info)
{
	switch (ELF64_ST_TYPE(info)) {
	case STT_NOTYPE:
		return "NOTYPE";
	case STT_OBJECT:
		return "OBJECT";
	case STT_FUNC:
		return "FUNC";
	case STT_SECTION:
		return "SECTION";
	case STT_FILE:
		return "FILE";
	case STT_COMMON:
		return "COMMON";
	case STT_TLS:
		return "TLS";
	case STT_NUM:
		return "NUM";
	case STT_LOOS:
		return "LOOS";
	case STT_HIOS:
		return "HIOS";
	case STT_LOPROC:
		return "LOPROC";
	case STT_HIPROC:
		return "HIPROC";
	default:
		return "UNKNOWN";
	}
}

std::string ElfGetSymbolBindString(uint8_t info)
{
	switch (ELF64_ST_BIND(info)) {
	case STB_LOCAL:
		return "LOCAL";
	case STB_GLOBAL:
		return "GLOBAL";
	case STB_WEAK:
		return "WEAK";
	case STB_NUM:
		return "NUM";
	case STB_LOOS:
		return "LOOS";
	case STB_HIOS:
		return "HIOS";
	case STB_LOPROC:
		return "LOPROC";
	case STB_HIPROC:
		return "HIPROC";
	default:
		return "UNKNOWN";
	}
}

std::string ElfGetSymbolVisibleString(uint8_t other)
{
	switch (ELF64_ST_VISIBILITY(other)) {
	case STV_DEFAULT:
		return "DEFAULT";
	case STV_INTERNAL:
		return "INTERNAL";
	case STV_HIDDEN:
		return "HIDDEN";
	case STV_PROTECTED:
		return "PROTECTED";
	default:
		return "UNKNOWN";
	}
}

std::string ElfGetSymbolIndexString(uint32_t index)
{
	char buff[32] = {0};
	switch (index) {
	case SHN_UNDEF:	return "UND";
	case SHN_ABS: return "ABS";
	case SHN_COMMON: return "COM";
	default:
		sprintf(buff, "%d", index);
		break;
	}
	return buff;
}

std::string ElfGetRelocationTypeString(uint32_t type, uint16_t machine)
{
	if (machine == EM_X86_64) {
		switch (type) {
		case R_X86_64_64:
			return "R_X86_64_64";
		case R_X86_64_PC32:
			return "R_X86_64_PC32";
		case R_X86_64_GOT32:
			return "R_X86_64_GOT32";
		case R_X86_64_PLT32:
			return "R_X86_64_PLT32";
		case R_X86_64_RELATIVE:
			return "R_X86_64_RELATIVE";
		case R_X86_64_JUMP_SLOT:
			return "R_X86_64_JUMP_SLOT";
		}
	} else if (machine == EM_386) {
		switch (type) {
		case R_386_GOT32:
			return "R_386_GOT32";
		case R_386_PLT32:
			return "R_386_PLT32";
		case R_386_JMP_SLOT:
			return "R_386_JMP_SLOT";
		case R_386_RELATIVE:
			return "R_386_RELATIVE";
		case R_386_PC32:
			return "R_386_PC32";
		case R_386_32:
			return "R_386_32";
		}
	} else if (machine == EM_ARM) {
		switch (type) {
		case R_ARM_ABS32:
			return "R_ARM_ABS32";
		case R_ARM_GLOB_DAT:
			return "R_ARM_GLOB_DAT";
		case R_ARM_RELATIVE:
			return "R_ARM_RELATIVE";
		case R_ARM_JUMP_SLOT:
			return "R_ARM_JUMP_SLOT";
		}

	} else if (machine == EM_AARCH64) {
		switch (type) {
		case R_AARCH64_ABS16:
			return "R_AARCH64_ABS64";
		case R_AARCH64_ABS32:
			return "R_AARCH64_ABS32";
		case R_AARCH64_ABS64:
			return "R_AARCH64_ABS64";
		case R_AARCH64_GLOB_DAT:
			return "R_AARCH64_GLOB_DAT";
		case R_AARCH64_JUMP_SLOT:
			return "R_AARCH64_JUMP_SLOT";
		case R_AARCH64_RELATIVE:
			return "R_AARCH64_RELATIVE";
		}
	}
	return UNONE::StrFormatA("%08X", type);
}
}