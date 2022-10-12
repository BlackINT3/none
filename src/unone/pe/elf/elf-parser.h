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
#include <internal/unone-internal.h>

#ifndef NT_ARCH
#define NT_ARCH 2
#endif

namespace UNONE {

#define ELF_HEADER32(base) ((Elf32_Ehdr*)base)
#define ELF_HEADER64(base) ((Elf64_Ehdr*)base)
#define ELF_X64(base) (ELF_HEADER32(base)->e_ident[4] == ELFCLASS64)
#define ELF_PH_HEADER32(base) ((Elf32_Phdr*)((CHAR*)base + ELF_HEADER32(base)->e_phoff))
#define ELF_PH_HEADER64(base) ((Elf64_Phdr*)((CHAR*)base + ELF_HEADER64(base)->e_phoff))
#define ELF_SH_HEADER32(base) ((Elf32_Shdr*)((CHAR*)base + ELF_HEADER32(base)->e_shoff))
#define ELF_SH_HEADER64(base) ((Elf64_Shdr*)((CHAR*)base + ELF_HEADER64(base)->e_shoff))
#define ELF_SH_STRTAB32(base) ((ELF_SH_HEADER32(base)[ELF_HEADER32(base)->e_shstrndx]).sh_offset)
#define ELF_SH_STRTAB64(base) ((ELF_SH_HEADER64(base)[ELF_HEADER64(base)->e_shstrndx]).sh_offset)

UNONE_API bool ElfX64(__in CHAR* base);
UNONE_API bool ElfValid(__in CHAR* base);
UNONE_API uint64_t ElfGetEntryPoint(__in CHAR* base);
UNONE_API uint16_t ElfGetPHeaderNums(__in CHAR* base);
UNONE_API uint16_t ElfGetSectionHeaderNums(__in CHAR* base);
UNONE_API std::string ElfGetIdentEncoding(uint8_t code);
UNONE_API std::string ElfGetIdentClassString(uint8_t clazz);
UNONE_API std::string ElfGetIdentVersionString(uint8_t version);
UNONE_API std::string ElfGetIdentOSABIString(uint8_t osabi);
UNONE_API std::string ElfGetEHeaderTypeString(uint16_t type);
UNONE_API std::string ElfGetEHeaderMachineString(uint16_t machine);
UNONE_API std::string ElfGetPHeaderTypeString(uint32_t type);
UNONE_API std::string ElfGetPHeaderFlagString(uint32_t flags);
UNONE_API std::string ElfGetSectionName(CHAR* base, uint32_t offset);
UNONE_API std::string ElfGetSectionTypeString(uint32_t type);
UNONE_API std::string ElfGetSectionFlagString(uint32_t flags);
UNONE_API std::string ElfGetDynamicTypeString(uint32_t tag);
UNONE_API std::string ElfGetDynamicFlagString(uint32_t flag);
UNONE_API std::string ElfGetSymbolTypeString(uint8_t info);
UNONE_API std::string ElfGetSymbolBindString(uint8_t info);
UNONE_API std::string ElfGetSymbolVisibleString(uint8_t other);
UNONE_API std::string ElfGetSymbolIndexString(uint32_t index);
UNONE_API std::string ElfGetRelocationTypeString(uint32_t type, uint16_t machine);

} // namespace UNONE