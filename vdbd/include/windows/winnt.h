/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the VDBD runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */
#ifndef _WINNT_
#define _WINNT_

#include <cstdint>

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_OS2_SIGNATURE 0x454E
#define IMAGE_OS2_SIGNATURE_LE 0x454C
#define IMAGE_VXD_SIGNATURE 0x454C
#define IMAGE_NT_SIGNATURE 0x00004550

#pragma pack(2)

struct IMAGE_DOS_HEADER {
	uint16_t e_magic;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	int32_t e_lfanew;
};

struct IMAGE_OS2_HEADER {
	uint16_t ne_magic;
	int8_t ne_ver;
	int8_t ne_rev;
	uint16_t ne_enttab;
	uint16_t ne_cbenttab;
	int32_t ne_crc;
	uint16_t ne_flags;
	uint16_t ne_autodata;
	uint16_t ne_heap;
	uint16_t ne_stack;
	int32_t ne_csip;
	int32_t ne_sssp;
	uint16_t ne_cseg;
	uint16_t ne_cmod;
	uint16_t ne_cbnrestab;
	uint16_t ne_segtab;
	uint16_t ne_rsrctab;
	uint16_t ne_restab;
	uint16_t ne_modtab;
	uint16_t ne_imptab;
	int32_t ne_nrestab;
	uint16_t ne_cmovent;
	uint16_t ne_align;
	uint16_t ne_cres;
	uint8_t ne_exetyp;
	uint8_t ne_flagsothers;
	uint16_t ne_pretthunks;
	uint16_t ne_psegrefuint8_ts;
	uint16_t ne_swaparea;
	uint16_t ne_expver;
};

struct IMAGE_VXD_HEADER {
	uint16_t e32_magic;
	uint8_t e32_border;
	uint8_t e32_uint16_ter;
	uint32_t e32_level;
	uint16_t e32_cpu;
	uint16_t e32_os;
	uint32_t e32_ver;
	uint32_t e32_mflags;
	uint32_t e32_mpages;
	uint32_t e32_startobj;
	uint32_t e32_eip;
	uint32_t e32_stackobj;
	uint32_t e32_esp;
	uint32_t e32_pagesize;
	uint32_t e32_lastpagesize;
	uint32_t e32_fixupsize;
	uint32_t e32_fixupsum;
	uint32_t e32_ldrsize;
	uint32_t e32_ldrsum;
	uint32_t e32_objtab;
	uint32_t e32_objcnt;
	uint32_t e32_objmap;
	uint32_t e32_itermap;
	uint32_t e32_rsrctab;
	uint32_t e32_rsrccnt;
	uint32_t e32_restab;
	uint32_t e32_enttab;
	uint32_t e32_dirtab;
	uint32_t e32_dircnt;
	uint32_t e32_fpagetab;
	uint32_t e32_frectab;
	uint32_t e32_impmod;
	uint32_t e32_impmodcnt;
	uint32_t e32_impproc;
	uint32_t e32_pagesum;
	uint32_t e32_datapage;
	uint32_t e32_preload;
	uint32_t e32_nrestab;
	uint32_t e32_cbnrestab;
	uint32_t e32_nressum;
	uint32_t e32_autodata;
	uint32_t e32_debuginfo;
	uint32_t e32_debuglen;
	uint32_t e32_instpreload;
	uint32_t e32_instdemand;
	uint32_t e32_heapsize;
	uint8_t e32_res3[12];
	uint32_t e32_winresoff;
	uint32_t e32_winreslen;
	uint16_t e32_devid;
	uint16_t e32_ddkver;
};

#pragma pack()

struct IMAGE_FILE_HEADER {
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t int8_tacteristics;
};

#define IMAGE_SIZEOF_FILE_HEADER 20

#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
#define IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define IMAGE_FILE_uint8_tS_REVERSED_LO 0x0080
#define IMAGE_FILE_32BIT_MACHINE 0x0100
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800
#define IMAGE_FILE_SYSTEM 0x1000
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
#define IMAGE_FILE_uint8_tS_REVERSED_HI 0x8000

#define IMAGE_FILE_MACHINE_UNKNOWN 0
#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_FILE_MACHINE_R3000 0x0162
#define IMAGE_FILE_MACHINE_R4000 0x0166
#define IMAGE_FILE_MACHINE_R10000 0x0168
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x0169
#define IMAGE_FILE_MACHINE_ALPHA 0x0184
#define IMAGE_FILE_MACHINE_SH3 0x01a2
#define IMAGE_FILE_MACHINE_SH3DSP 0x01a3
#define IMAGE_FILE_MACHINE_SH3E 0x01a4
#define IMAGE_FILE_MACHINE_SH4 0x01a6
#define IMAGE_FILE_MACHINE_SH5 0x01a8
#define IMAGE_FILE_MACHINE_ARM 0x01c0
#define IMAGE_FILE_MACHINE_ARMV7 0x01c4
#define IMAGE_FILE_MACHINE_THUMB 0x01c2
#define IMAGE_FILE_MACHINE_AM33 0x01d3
#define IMAGE_FILE_MACHINE_POWERPC 0x01F0
#define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1
#define IMAGE_FILE_MACHINE_IA64 0x0200
#define IMAGE_FILE_MACHINE_MIPS16 0x0266
#define IMAGE_FILE_MACHINE_ALPHA64 0x0284
#define IMAGE_FILE_MACHINE_MIPSFPU 0x0366
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x0466
#define IMAGE_FILE_MACHINE_AXP64 IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE 0x0520
#define IMAGE_FILE_MACHINE_CEF 0x0CEF
#define IMAGE_FILE_MACHINE_EBC 0x0EBC
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_M32R 0x9041
#define IMAGE_FILE_MACHINE_CEE 0xC0EE

struct IMAGE_DATA_DIRECTORY {
	uint32_t VirtualAddress;
	uint32_t Size;
};

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

    typedef struct _IMAGE_OPTIONAL_HEADER {

      uint16_t Magic;
      uint8_t MajorLinkerVersion;
      uint8_t MinorLinkerVersion;
      uint32_t SizeOfCode;
      uint32_t SizeOfInitializedData;
      uint32_t SizeOfUninitializedData;
      uint32_t AddressOfEntryPoint;
      uint32_t BaseOfCode;
      uint32_t BaseOfData;
      uint32_t ImageBase;
      uint32_t SectionAlignment;
      uint32_t FileAlignment;
      uint16_t MajorOperatingSystemVersion;
      uint16_t MinorOperatingSystemVersion;
      uint16_t MajorImageVersion;
      uint16_t MinorImageVersion;
      uint16_t MajorSubsystemVersion;
      uint16_t MinorSubsystemVersion;
      uint32_t Win32VersionValue;
      uint32_t SizeOfImage;
      uint32_t SizeOfHeaders;
      uint32_t CheckSum;
      uint16_t Subsystem;
      uint16_t Dllint8_tacteristics;
      uint32_t SizeOfStackReserve;
      uint32_t SizeOfStackCommit;
      uint32_t SizeOfHeapReserve;
      uint32_t SizeOfHeapCommit;
      uint32_t LoaderFlags;
      uint32_t NumberOfRvaAndSizes;
      IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER32,*PIMAGE_OPTIONAL_HEADER32;

    typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
      uint16_t Magic;
      uint8_t MajorLinkerVersion;
      uint8_t MinorLinkerVersion;
      uint32_t SizeOfCode;
      uint32_t SizeOfInitializedData;
      uint32_t SizeOfUninitializedData;
      uint32_t AddressOfEntryPoint;
      uint32_t BaseOfCode;
      uint32_t BaseOfData;
      uint32_t BaseOfBss;
      uint32_t GprMask;
      uint32_t CprMask[4];
      uint32_t GpValue;
    } IMAGE_ROM_OPTIONAL_HEADER,*PIMAGE_ROM_OPTIONAL_HEADER;

    typedef struct _IMAGE_OPTIONAL_HEADER64 {
      uint16_t Magic;
      uint8_t MajorLinkerVersion;
      uint8_t MinorLinkerVersion;
      uint32_t SizeOfCode;
      uint32_t SizeOfInitializedData;
      uint32_t SizeOfUninitializedData;
      uint32_t AddressOfEntryPoint;
      uint32_t BaseOfCode;
      uint64_t ImageBase;
      uint32_t SectionAlignment;
      uint32_t FileAlignment;
      uint16_t MajorOperatingSystemVersion;
      uint16_t MinorOperatingSystemVersion;
      uint16_t MajorImageVersion;
      uint16_t MinorImageVersion;
      uint16_t MajorSubsystemVersion;
      uint16_t MinorSubsystemVersion;
      uint32_t Win32VersionValue;
      uint32_t SizeOfImage;
      uint32_t SizeOfHeaders;
      uint32_t CheckSum;
      uint16_t Subsystem;
      uint16_t Dllint8_tacteristics;
      uint64_t SizeOfStackReserve;
      uint64_t SizeOfStackCommit;
      uint64_t SizeOfHeapReserve;
      uint64_t SizeOfHeapCommit;
      uint32_t LoaderFlags;
      uint32_t NumberOfRvaAndSizes;
      IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER64,*PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_SIZEOF_ROM_OPTIONAL_HEADER 56
#define IMAGE_SIZEOF_STD_OPTIONAL_HEADER 28
#define IMAGE_SIZEOF_NT_OPTIONAL32_HEADER 224
#define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER 240

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC 0x107

#ifdef _WIN64
    typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
    typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else  /* _WIN64 */
    typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
    typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif /* _WIN64 */

    typedef struct _IMAGE_NT_HEADERS64 {
      uint32_t Signature;
      IMAGE_FILE_HEADER FileHeader;
      IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64,*PIMAGE_NT_HEADERS64;

    typedef struct _IMAGE_NT_HEADERS {
      uint32_t Signature;
      IMAGE_FILE_HEADER FileHeader;
      IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32,*PIMAGE_NT_HEADERS32;

    typedef struct _IMAGE_ROM_HEADERS {
      IMAGE_FILE_HEADER FileHeader;
      IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
    } IMAGE_ROM_HEADERS,*PIMAGE_ROM_HEADERS;

#ifdef _WIN64
    typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#else  /* _WIN64 */
    typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif /* _WIN64 */

#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER) ((Uint32_t_PTR)ntheader + FIELD_OFFSET(IMAGE_NT_HEADERS,OptionalHeader) + ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))

#define IMAGE_SUBSYSTEM_UNKNOWN 0
#define IMAGE_SUBSYSTEM_NATIVE 1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#define IMAGE_SUBSYSTEM_OS2_CUI 5
#define IMAGE_SUBSYSTEM_POSIX_CUI 7
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS 8
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 9
#define IMAGE_SUBSYSTEM_EFI_APPLICATION 10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12
#define IMAGE_SUBSYSTEM_EFI_ROM 13
#define IMAGE_SUBSYSTEM_XBOX 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

#define IMAGE_DLLint8_tACTERISTICS_DYNAMIC_BASE 0x0040
#define IMAGE_DLLint8_tACTERISTICS_FORCE_INTEGRITY 0x0080
#define IMAGE_DLLint8_tACTERISTICS_NX_COMPAT 0x0100
#define IMAGE_DLLint8_tACTERISTICS_NO_ISOLATION 0x0200
#define IMAGE_DLLint8_tACTERISTICS_NO_SEH 0x0400
#define IMAGE_DLLint8_tACTERISTICS_NO_BIND 0x0800
#define IMAGE_DLLint8_tACTERISTICS_WDM_DRIVER 0x2000
#define IMAGE_DLLint8_tACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6

#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

    typedef struct ANON_OBJECT_HEADER {
      uint16_t Sig1;
      uint16_t Sig2;
      uint16_t Version;
      uint16_t Machine;
      uint32_t TimeDateStamp;
      CLSID ClassID;
      uint32_t SizeOfData;
    } ANON_OBJECT_HEADER;

#define IMAGE_SIZEOF_SHORT_NAME 8

    typedef struct _IMAGE_SECTION_HEADER {
      uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
      union {
	uint32_t PhysicalAddress;
	uint32_t VirtualSize;
      } Misc;
      uint32_t VirtualAddress;
      uint32_t SizeOfRawData;
      uint32_t PointerToRawData;
      uint32_t PointerToRelocations;
      uint32_t PointerToLinenumbers;
      uint16_t NumberOfRelocations;
      uint16_t NumberOfLinenumbers;
      uint32_t int8_tacteristics;
    } IMAGE_SECTION_HEADER,*PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER 40

#define IMAGE_SCN_TYPE_NO_PAD 0x00000008

#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_LNK_OTHER 0x00000100
#define IMAGE_SCN_LNK_INFO 0x00000200
#define IMAGE_SCN_LNK_REMOVE 0x00000800
#define IMAGE_SCN_LNK_COMDAT 0x00001000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC 0x00004000
#define IMAGE_SCN_GPREL 0x00008000
#define IMAGE_SCN_MEM_FARDATA 0x00008000
#define IMAGE_SCN_MEM_PURGEABLE 0x00020000
#define IMAGE_SCN_MEM_16BIT 0x00020000
#define IMAGE_SCN_MEM_LOCKED 0x00040000
#define IMAGE_SCN_MEM_PRELOAD 0x00080000

#define IMAGE_SCN_ALIGN_1uint8_tS 0x00100000
#define IMAGE_SCN_ALIGN_2uint8_tS 0x00200000
#define IMAGE_SCN_ALIGN_4uint8_tS 0x00300000
#define IMAGE_SCN_ALIGN_8uint8_tS 0x00400000
#define IMAGE_SCN_ALIGN_16uint8_tS 0x00500000
#define IMAGE_SCN_ALIGN_32uint8_tS 0x00600000
#define IMAGE_SCN_ALIGN_64uint8_tS 0x00700000
#define IMAGE_SCN_ALIGN_128uint8_tS 0x00800000
#define IMAGE_SCN_ALIGN_256uint8_tS 0x00900000
#define IMAGE_SCN_ALIGN_512uint8_tS 0x00A00000
#define IMAGE_SCN_ALIGN_1024uint8_tS 0x00B00000
#define IMAGE_SCN_ALIGN_2048uint8_tS 0x00C00000
#define IMAGE_SCN_ALIGN_4096uint8_tS 0x00D00000
#define IMAGE_SCN_ALIGN_8192uint8_tS 0x00E00000

#define IMAGE_SCN_ALIGN_MASK 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
#define IMAGE_SCN_MEM_SHARED 0x10000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

#define IMAGE_SCN_SCALE_INDEX 0x00000001

#pragma pack(2)

    typedef struct _IMAGE_SYMBOL {
      union {
	uint8_t ShortName[8];
	struct {
	  uint32_t Short;
	  uint32_t int32_t;
	} Name;
	uint32_t int32_tName[2];
      } N;
      uint32_t Value;
      SHORT SectionNumber;
      uint16_t Type;
      uint8_t StorageClass;
      uint8_t NumberOfAuxSymbols;
    } IMAGE_SYMBOL;
    typedef IMAGE_SYMBOL UNALIGNED *PIMAGE_SYMBOL;

#define IMAGE_SIZEOF_SYMBOL 18

#define IMAGE_SYM_UNDEFINED (SHORT)0
#define IMAGE_SYM_ABSOLUTE (SHORT)-1
#define IMAGE_SYM_DEBUG (SHORT)-2
#define IMAGE_SYM_SECTION_MAX 0xFEFF
#define IMAGE_SYM_SECTION_MAX_EX MAXint32_t

#define IMAGE_SYM_TYPE_NULL 0x0000
#define IMAGE_SYM_TYPE_VOID 0x0001
#define IMAGE_SYM_TYPE_int8_t 0x0002
#define IMAGE_SYM_TYPE_SHORT 0x0003
#define IMAGE_SYM_TYPE_INT 0x0004
#define IMAGE_SYM_TYPE_int32_t 0x0005
#define IMAGE_SYM_TYPE_FLOAT 0x0006
#define IMAGE_SYM_TYPE_DOUBLE 0x0007
#define IMAGE_SYM_TYPE_STRUCT 0x0008
#define IMAGE_SYM_TYPE_UNION 0x0009
#define IMAGE_SYM_TYPE_ENUM 0x000A
#define IMAGE_SYM_TYPE_MOE 0x000B
#define IMAGE_SYM_TYPE_uint8_t 0x000C
#define IMAGE_SYM_TYPE_uint16_t 0x000D
#define IMAGE_SYM_TYPE_UINT 0x000E
#define IMAGE_SYM_TYPE_uint32_t 0x000F
#define IMAGE_SYM_TYPE_PCODE 0x8000

#define IMAGE_SYM_DTYPE_NULL 0
#define IMAGE_SYM_DTYPE_POINTER 1
#define IMAGE_SYM_DTYPE_FUNCTION 2
#define IMAGE_SYM_DTYPE_ARRAY 3

#define IMAGE_SYM_CLASS_END_OF_FUNCTION (uint8_t)-1
#define IMAGE_SYM_CLASS_NULL 0x0000
#define IMAGE_SYM_CLASS_AUTOMATIC 0x0001
#define IMAGE_SYM_CLASS_EXTERNAL 0x0002
#define IMAGE_SYM_CLASS_STATIC 0x0003
#define IMAGE_SYM_CLASS_REGISTER 0x0004
#define IMAGE_SYM_CLASS_EXTERNAL_DEF 0x0005
#define IMAGE_SYM_CLASS_LABEL 0x0006
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL 0x0007
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT 0x0008
#define IMAGE_SYM_CLASS_ARGUMENT 0x0009
#define IMAGE_SYM_CLASS_STRUCT_TAG 0x000A
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION 0x000B
#define IMAGE_SYM_CLASS_UNION_TAG 0x000C
#define IMAGE_SYM_CLASS_TYPE_DEFINITION 0x000D
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC 0x000E
#define IMAGE_SYM_CLASS_ENUM_TAG 0x000F
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM 0x0010
#define IMAGE_SYM_CLASS_REGISTER_PARAM 0x0011
#define IMAGE_SYM_CLASS_BIT_FIELD 0x0012
#define IMAGE_SYM_CLASS_FAR_EXTERNAL 0x0044
#define IMAGE_SYM_CLASS_BLOCK 0x0064
#define IMAGE_SYM_CLASS_FUNCTION 0x0065
#define IMAGE_SYM_CLASS_END_OF_STRUCT 0x0066
#define IMAGE_SYM_CLASS_FILE 0x0067
#define IMAGE_SYM_CLASS_SECTION 0x0068
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL 0x0069
#define IMAGE_SYM_CLASS_CLR_TOKEN 0x006B

#define N_BTMASK 0x000F
#define N_TMASK 0x0030
#define N_TMASK1 0x00C0
#define N_TMASK2 0x00F0
#define N_BTSHFT 4
#define N_TSHIFT 2

#define BTYPE(x) ((x) & N_BTMASK)

#ifndef ISPTR
#define ISPTR(x) (((x) & N_TMASK)==(IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
#endif

#ifndef ISFCN
#define ISFCN(x) (((x) & N_TMASK)==(IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
#endif

#ifndef ISARY
#define ISARY(x) (((x) & N_TMASK)==(IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
#endif

#ifndef ISTAG
#define ISTAG(x) ((x)==IMAGE_SYM_CLASS_STRUCT_TAG || (x)==IMAGE_SYM_CLASS_UNION_TAG || (x)==IMAGE_SYM_CLASS_ENUM_TAG)
#endif

#ifndef INCREF
#define INCREF(x) ((((x)&~N_BTMASK)<<N_TSHIFT)|(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT)|((x)&N_BTMASK))
#endif
#ifndef DECREF
#define DECREF(x) ((((x)>>N_TSHIFT)&~N_BTMASK)|((x)&N_BTMASK))
#endif

    typedef union _IMAGE_AUX_SYMBOL {
      struct {
	uint32_t TagIndex;
	union {
	  struct {
	    uint16_t Linenumber;
	    uint16_t Size;
	  } LnSz;
	  uint32_t TotalSize;
	} Misc;
	union {
	  struct {
	    uint32_t PointerToLinenumber;
	    uint32_t PointerToNextFunction;
	  } Function;
	  struct {
	    uint16_t Dimension[4];
	  } Array;
	} FcnAry;
	uint16_t TvIndex;
      } Sym;
      struct {
	uint8_t Name[IMAGE_SIZEOF_SYMBOL];
      } File;
      struct {
	uint32_t Length;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t CheckSum;
	SHORT Number;
	uint8_t Selection;
      } Section;
    } IMAGE_AUX_SYMBOL;
    typedef IMAGE_AUX_SYMBOL UNALIGNED *PIMAGE_AUX_SYMBOL;

#define IMAGE_SIZEOF_AUX_SYMBOL 18

    typedef enum IMAGE_AUX_SYMBOL_TYPE {
      IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1
    } IMAGE_AUX_SYMBOL_TYPE;

#pragma pack(2)

    typedef struct IMAGE_AUX_SYMBOL_TOKEN_DEF {
      uint8_t bAuxType;
      uint8_t bReserved;
      uint32_t SymbolTableIndex;
      uint8_t rgbReserved[12];
    } IMAGE_AUX_SYMBOL_TOKEN_DEF;

    typedef IMAGE_AUX_SYMBOL_TOKEN_DEF UNALIGNED *PIMAGE_AUX_SYMBOL_TOKEN_DEF;



#endif