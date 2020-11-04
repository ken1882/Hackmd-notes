---
tags: security, notes
title: Life of Binaries
---

# Life of Binaries

[TOC]

## Different Type of Binaries
* COFF (Common Object File Format)
    * Was introduced back with UNIX System V
* Portable Executable (PE)
    * Windows
* Executable and Linkable Format (ELF)
    * Modern Linux
* Mach Object (Mach-o)
    * Mac OS X
* Executable
    * `.exe` on Windows
    * No suffix on Linux
* Dynamic Link Library
    * `.dll` on Windows
    * `.so` (Shared Object) on Linux
        * May automatically execute code on loaded by other program (`DLLMAIN()` on Windows and `init()` on Linux) which is different than standard knowledge of a library
* Static Library
    * `.lib` on Windows
    * `.a` on Linux
    * Basically collection of object files with some header info

## PE Overview
![](https://i.imgur.com/0eqi3Ru.png)


### DOS Header
```c
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;      /* 00: MZ Header signature */
    WORD  e_cblp;       /* 02: Bytes on last page of file */
    WORD  e_cp;         /* 04: Pages in file */
    WORD  e_crlc;       /* 06: Relocations */
    WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
    WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
    WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
    WORD  e_ss;         /* 0e: Initial (relative) SS value */
    WORD  e_sp;         /* 10: Initial SP value */
    WORD  e_csum;       /* 12: Checksum */
    WORD  e_ip;         /* 14: Initial IP value */
    WORD  e_cs;         /* 16: Initial (relative) CS value */
    WORD  e_lfarlc;     /* 18: File address of relocation table */
    WORD  e_ovno;       /* 1a: Overlay number */
    WORD  e_res[4];     /* 1c: Reserved words */
    WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
    WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
    WORD  e_res2[10];   /* 28: Reserved words */
    DWORD e_lfanew;     /* 3c: Offset to extended header */
}
```
* Important attribute:
    * e_magic: Usually set to `MZ` stands for Mark Zbikowski who developed MS-DOS
    * e_lfanew: Offset to he `IMAGE_NT_HEADER`
* Most Windows programs has a stub in this header that just prints "This program cannot be run in DOS mode"

### Image NT Header
```c
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
  ULONG Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```
* `Signature`: usually `0x5045`, aka `PE` in ASCII

### Image File Header
```c
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```
* [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header)
* Important Attributes:
    * **`Machine`:** Machine architecture
        * `IMAGE_FILE_MACHINE_I386` (`0x014c`, aka x86)
        * `IMAGE_FILE_MACHINE_AMD64` (`0x8664`, aka x64)
        * `IMAGE_FILE_MACHINE_IA64` (`0x0200`, Intel Itanium ???)
    * **`NumberOfSections`**: Indicates the size of the section headers.
    * **`TimeDateStamp`**: Unix timestamp (seconds since epoc, aka `1970/1/1 00:00 UTC+0`) and is set at link time.
    * **`Characteristics`**: Bitmask of the PE attributes:

| Name | Value | Meaning |
| -------- | -------- | --- |
| IMAGE_FILE_RELOCS_STRIPPED | 0x0001 | Relocation information was stripped from the file. The file must be loaded at its preferred base address. If the base address is not available, the loader reports an error.     | 
| IMAGE_FILE_EXECUTABLE_IMAGE | 0x0002 | The file is executable (there are no unresolved external references).  |
| IMAGE_FILE_LINE_NUMS_STRIPPED | 0x0004 | COFF line numbers were stripped from the file.  |
| IMAGE_FILE_LOCAL_SYMS_STRIPPED | 0x0008 | COFF symbol table entries were stripped from file.  |
| IMAGE_FILE_AGGRESIVE_WS_TRIM | 0x0010 | Aggressively trim the working set. This value is obsolete. |
| IMAGE_FILE_LARGE_ADDRESS_AWARE | 0x0020 | The application can handle addresses larger than 2 GB. (2^31-1) |
| IMAGE_FILE_BYTES_REVERSED_LO | 0x0080 | The bytes of the word are reversed. This flag is obsolete. |
| IMAGE_FILE_32BIT_MACHINE | 0x0100 | The computer supports 32-bit words. |
| IMAGE_FILE_DEBUG_STRIPPED |0x0200 | Debugging information was removed and stored separately in another file. |
| IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP | 0x0400 | If the image is on removable media, copy it to and run it from the swap file. |
| IMAGE_FILE_NET_RUN_FROM_SWAP | 0x0800 | If the image is on the network, copy it to and run it from the swap file. |
| IMAGE_FILE_SYSTEM | 0x1000 | The image is a system file. (Nobody uses it nowadays) |
| IMAGE_FILE_DLL | 0x2000 | The image is a DLL file. While it is an executable file, it cannot be run directly. |
| IMAGE_FILE_UP_SYSTEM_ONLY | 0x4000 | The file should be run only on a uniprocessor computer. |
| IMAGE_FILE_BYTES_REVERSED_HI | 0x8000 | The bytes of the word are reversed. This flag is obsolete. |

### Optional Header (not optional at all)
```c
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  ULONGLONG            ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  ULONGLONG            SizeOfStackReserve;
  ULONGLONG            SizeOfStackCommit;
  ULONGLONG            SizeOfHeapReserve;
  ULONGLONG            SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```
* Important attributes:
    * **`Magic`**
        * IMAGE_NT_OPTIONAL_HDR32_MAGIC (0x10b): 32-bits executable
        * IMAGE_NT_OPTIONAL_HDR64_MAGIC (0x20b): 64-bits executable
        * IMAGE_ROM_OPTIONAL_HDR_MAGIC (0x107): ROM image
    * **`AddressOfEntryPoint`**: A pointer to the entry point function, relative to the image base address. For executable files, this is the starting address. For device drivers, this is the address of the initialization function. The entry point function is optional for DLLs. When no entry point is present, this member is zero. Can be tweaked to execute other stuff and back to original pointer later on.
    * **`ImageBase`**: Preferred virtual memory address the image to be loaded, if the address is occupied, the image has to follow relocation table to rebase to other address. Default location are:
        * DLL: 0x10000000
        * EXE: 0x00400000
        * Windows CE: 0x00010000
    * **`SectionAlignment`**: Memory alignment for sections. Default value is system page size and must `>= FileAlignment`. (Commonly 0x1000)
    * **`FileAlignment`**: Defines binary chunk alignment of the PE itself in disk. Default is 0x200 (bytes) in HDD and 0x80 in floppy. Value must `== SectionAlignment if SectionAlignment <= SYSTEM_PAGE_SIZE`
    * **`SizeOfImage`**: amount of contiguous memory must be allocated for this PE to map onto memory, and must be multiple of `SectionAlignment`
    * **`DllCharacteristics`**

| Name | Value | Meaning |
| --- | --- | --- |
| - | 0x0001 | Reserved. |
| - | 0x0002 | Reserved. |
| - | 0x0004 | Reserved. |
| - | 0x0008 | Reserved.| 
| IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | 0x0040| The DLL can be relocated at load time. |
| IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY | 0x0080 | Code integrity checks are forced. If you set this flag and a section contains only uninitialized data, set the PointerToRawData member of IMAGE_SECTION_HEADER for that section to zero; otherwise, the image will fail to load because the digital signature cannot be verified.  |
| IMAGE_DLLCHARACTERISTICS_NX_COMPAT | 0x0100 | The image is compatible with data execution prevention (DEP).  |
| IMAGE_DLLCHARACTERISTICS_NO_ISOLATION | 0x0200 | The image is isolation aware, but should not be isolated.  |
| IMAGE_DLLCHARACTERISTICS_NO_SEH | 0x0400 | The image does not use structured exception handling (SEH). No handlers can be called in this image.  |
| IMAGE_DLLCHARACTERISTICS_NO_BIND | 0x0800 | Do not bind the image.  |
| - | 0x1000| Reserved.  |
| IMAGE_DLLCHARACTERISTICS_WDM_DRIVER| 0x2000| A WDM driver. |
| -| 0x4000| Reserved. |
| IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE| 0x8000| The image is terminal server aware. |
* **`DataDirectory`**: Pointer to array of IMAGE_DATA_DIRECTORY[16]

| Name | Value | Meaning |
| --- | --- | --- |
| IMAGE_DIRECTORY_ENTRY_EXPORT | 0 | Export directory  |
| IMAGE_DIRECTORY_ENTRY_IMPORT | 1 | Import directory  |
| IMAGE_DIRECTORY_ENTRY_RESOURCE | 2 | Resource directory |
| IMAGE_DIRECTORY_ENTRY_EXCEPTION | 3 | Exception directory  |
| IMAGE_DIRECTORY_ENTRY_SECURITY | 4 | Security directory  |
| IMAGE_DIRECTORY_ENTRY_BASERELOC | 5 | Base relocation table  |
| IMAGE_DIRECTORY_ENTRY_DEBUG | 6 | Debug directory  |
| IMAGE_DIRECTORY_ENTRY_ARCHITECTURE |  7| Architecture-specific data  |
| IMAGE_DIRECTORY_ENTRY_GLOBALPTR | 8 | The relative virtual address of global pointer  |
| IMAGE_DIRECTORY_ENTRY_TLS | 9 | Thread local storage directory  |
| IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG | 10 | Load configuration directory  |
| IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT | 11 | Bound import directory  |
| IMAGE_DIRECTORY_ENTRY_IAT | 12 | Import address table  |
| IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT | 13 | Delay import table  |
| IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR | 14 | COM descriptor table  |
| - | 15 | Reserved |

### Section Headers
Groups portions of code or data that have similar purpose or permission.

* Common names
    * `.text`: Code which should never be paged out of memory to disk
    * `.data`: Read/Write data
    * `.rdata`: Read-only data
    * `.bss`: Multiple names: Block Storage Segment / Block Started by Symbol / Block Storage Start
    * `.idata`: Import address table
    * `.edata`: Export information
    * `*PAGE`: Code/data that allowed page to disk if low memory
    * `.reloc`: Relocation information
    * `.rsrc`: Resources. Including icons, embedded binaries etc. Has its own file structure
    * `.pdata`: Array of `RUNTIME_FUNCTION` with RVA to their corresponding `UNWIND_INFO` in stack walking for debug purpose and exception handling.

```c
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```
* **Important attributes**:
    * **`Name[8]`**: byte array of ASCII characters, NOT guaranteed to be null-terminated which should be noticed when parsing PE manually.
    * **`VirtualAddress`**: RVA of this section to `OptionalHeader.ImageBase`
    * **`PointerToRawData`**: Relative offset to actual code data of this section.
    * **`Characteristics`**: 

| Name | Value | Meaning |
| --- | --- | --- |
| - | 0x00000000 | Reserved |
| - | 0x00000001 | Reserved |
| - | 0x00000002 | Reserved |
| - | 0x00000004 | Reserved |
| MAGE_SCN_TYPE_NO_PAD | 0x00000008 | The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. |
| - | 0x00000010 | Reserved. |
| IMAGE_SCN_CNT_CODE | 0x00000020 | The section contains executable code. |
| IMAGE_SCN_CNT_INITIALIZED_DATA | 0x00000040 | The section contains initialized data. |
| IMAGE_SCN_CNT_UNINITIALIZED_DATA | 0x00000080 | The section contains uninitialized data. |
| IMAGE_SCN_LNK_OTHER | 0x00000100 | Reserved. |
| IMAGE_SCN_LNK_INFO | 0x00000200 | The section contains comments or other information. This is valid only for object files. |
| - | 0x00000400 | Reserved. |
| IMAGE_SCN_LNK_REMOVE | 0x00000800 | The section will not become part of the image. This is valid only for object files. |
| IMAGE_SCN_LNK_COMDAT | 0x00001000 | The section contains COMDAT data. This is valid only for object files. |
| - | 0x00002000 | Reserved. |
| IMAGE_SCN_NO_DEFER_SPEC_EXC | 0x00004000 | Reset speculative exceptions handling bits in the TLB entries for this section. |
| IMAGE_SCN_GPREL | 0x00008000 | The section contains data referenced through the global pointer. |
| - | 0x00010000 | Reserved. |
| IMAGE_SCN_MEM_PURGEABLE | 0x00020000 | Reserved. |
| IMAGE_SCN_MEM_LOCKED | 0x00040000 | Reserved. |
| IMAGE_SCN_MEM_PRELOAD | 0x00080000 | Reserved.|
| IMAGE_SCN_ALIGN_1BYTES | 0x00100000 | Align data on a 1-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_2BYTES | 0x00200000 | Align data on a 2-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_4BYTES | 0x00300000 | Align data on a 4-byte boundary. This is valid only for object files. | 
| IMAGE_SCN_ALIGN_8BYTES | 0x00400000 | Align data on a 8-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_16BYTES | 0x00500000 | Align data on a 16-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_32BYTES | 0x00600000 | Align data on a 32-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_64BYTES | 0x00700000 | Align data on a 64-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_128BYTES | 0x00800000 | Align data on a 128-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_256BYTES | 0x00900000 | Align data on a 256-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_512BYTES | 0x00A00000 | Align data on a 512-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_1024BYTES | 0x00B00000 | Align data on a 1024-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_2048BYTES | 0x00C00000 | Align data on a 2048-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_4096BYTES | 0x00D00000 | Align data on a 4096-byte boundary. This is valid only for object files. |
| IMAGE_SCN_ALIGN_8192BYTES | 0x00E00000 | Align data on a 8192-byte boundary. This is valid only for object files. |
| IMAGE_SCN_LNK_NRELOC_OVFL | 0x01000000 | The section contains extended relocations. The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header. If the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in the VirtualAddress field of the first relocation. It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section. |
| IMAGE_SCN_MEM_DISCARDABLE | 0x02000000 | The section can be discarded as needed. |
| IMAGE_SCN_MEM_NOT_CACHED | 0x04000000 | The section cannot be cached. |
| IMAGE_SCN_MEM_NOT_PAGED | 0x08000000 | The section cannot be paged. |
| IMAGE_SCN_MEM_SHARED | 0x10000000 | The section can be shared in memory. | 
| IMAGE_SCN_MEM_EXECUTE | 0x20000000 | The section can be executed as code. |
| IMAGE_SCN_MEM_READ | 0x40000000 | The section can be read. |
| IMAGE_SCN_MEM_WRITE | 0x80000000 | The section can be written to. |

### Imports
#### Static Linking
Compiler includes every helper function called by the program. Standalone and no external dependencies required. However makes program load slower and bigger.

#### Dynamic Linking
Compiler generate function symbols and pointers are resolved by linker to libraries in run time.

* The data directory:
```c
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```
And the `VirtualAddress` is pointed to:
```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  union {
    // 0 for terminating null import descriptor
    DWORD Characteristics;      
    // RVA to original unbound INT (Import Name Table)
    PIMAGE_THUNK_DATA OriginalFirstThunk;
  } u;
  
  // Will be different depending on import method
  // see below import sections for more info
  DWORD    TimeDateStamp;
  DWORD    ForwarderChain; // -1 if none
  DWORD    Name;
  DWORD    FirstThunk; // RVA to IAT
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;
```
![](https://i.imgur.com/UUCOf25.png)

and INT is an array of `IMAGE_THUNK_DATA`, with each represents either an imported function or ordinal.

```c 
struct _IMAGE_THUNK_DATA32{
  union {
    DWORD ForwarderString 
    
    // the memory address of the function being input
    DWORD Function 
    
    // The ordinal value of the API being entered.
    DWORD Ordinal 
    
    // Pointer to IMAGE_IMPORT_BY_NAME structure
    // aka `PIMAGE_IMPORT_BY_NAME AddressOfData;`
    DWORD AddressOfData
    
    }u1;
}} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

struct _IMAGE_THUNK_DATA64{
  union {
    ULONGLONG ForwarderString 
    ULONGLONG Function 
    ULONGLONG Ordinal 
    ULONGLONG AddressOfData
    }u1;
}} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;
```
* **`Ordinal`:**
If the highest bit IS set, the lower part of this value is the ordinal (and is also the "hint" value). The function is therefore imported by ordinal and there is no name available.
* **`AddressOfData`:**
If the high-bit is NOT set, the whole value is a RVA (pointer to memory image, without the base) to a `IMAGE_IMPORT_BY_NAME` structure. If reading from the file image, this value has to be converted to a file offset from the RVA.

```c
struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;                 
    BYTE    Name[1];            
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```
* **`Hint`:**
Possible 'ordinal' of an imported function, basically a way to look up the function by index rather than name.
* **`Name`:**
Look up the function by name, obviously not one byte long but a null-terminated ASCII string. Usually null.

### Bounded Imports
* Import binding is an optimization technique that imported function address are resolved during link time then placed into IAT when compiled.
* If the DLL changes, the pre-built IAT will be invalid and it's not much worse than hadn't pre-built IAT because still have to manually resolve the IAT anyway.
* The `TimeDateStamp` in `IMAGE_IMPORT_DESCRIPTOR` will be `0` if not bounded, `-1` if vice versa. And the real timestamp will be in `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT` (new bind, aka `DataDirectory[11]`)
```c
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
      DWORD TimeDateStamp;     
      WORD OffsetModuleName; 
      WORD NumberOfModuleForwarderRefs;  
} IMAGE_BOUND_IMPORT_DESCRIPTOR, *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF {
         DWORD TimeDateStamp;
         WORD OffsetModuleName;
         WORD Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;
```
 * `TimeDateStamp`: The real timestamp in imports
 * `OffsetModuleName`: Offset the the module (dll)
 * `NumberOfModuleForwarderRefs`: Usually `0` unless this dll calls another dll, for example `kernel32.dll` forwards to `ntdll.dll`. This indicates the next `sizeof(IMAGE_BOUND_FORWARDER_REF) * NumberOfModuleForwarderRefs` bytes are `IMAGE_BOUND_FORWARDER_REF` instead of `IMAGE_BOUND_IMPORT_DESCRIPTOR` (they both has same size anyway).
#### ASLR (Address Space Layout Randomization) and the Binding import could not be presented at the same time
* If ASLR'd, address are going to change and the bounded address will be invalid anyway

### Delayed Imports
* DLLs that won't be loaded into memory until first time it's called (load-on-demand / lazy-loading)
```c
typedef struct _IMAGE_DELAY_IMPORT_DESCRIPTOR {
	DWORD		Flags;
	DWORD		Name;
	DWORD		Module;
	DWORD		FirstThunk;
	DWORD		OriginalFirstThunk;
	DWORD		BoundIAT;
	DWORD		UnloadIAT;
	DWORD		TimeDateStamp;
} IMAGE_DELAY_IMPORT_DESCRIPTOR, *PIMAGE_DELAY_IMPORT_DESCRIPTOR;
```

the attributes are basically explain in:

```c 
typedef struct ImgDelayDescr {
    DWORD        grAttrs;        // attributes
    RVA          rvaDLLName;     // RVA to dll name
    RVA          rvaHmod;        // RVA of module handle
    RVA          rvaIAT;         // RVA of the IAT
    RVA          rvaINT;         // RVA of the INT
    RVA          rvaBoundIAT;    // RVA of the optional bound IAT
    RVA          rvaUnloadIAT;   // RVA of optional copy of original IAT
    DWORD        dwTimeStamp;    // 0 if not bound,
                                 // O.W. date/time stamp of DLL bound to (Old BIND)
} ImgDelayDescr, * PImgDelayDescr;
```

* During runtime OS lookup the function in IAT, aka `DataDirectory[12]`, which could be tweaked.
* The asm will be like:
```x86asm
// UxTheme.dll
0x5AD72BEF <DrawThemeBackground>

// .text
// ...
call 0x103E6C4 <DrawThemeBackground>
// ...
call 0x103E6C4 <DrawThemeBackground>
// ...

// stub code
// <DLL Loading and resoultion proc>
mov eax,mspaint.exe+0x3E6C4
jmp mspaint.exe+0x3540A

// Delay load IAT
// ...
// <Load stub if DLL not loaded>
0x103E6C4 call eax
0x193E6C9 ret
// ...
```
#### Runtime Importing
* `LoadLibrary` `GetProcAddress` are used
* Abused by hackers (and modders)

### Export
* Export by name
* Export by ordinal (aka index)
```c 
struct IMAGE_EXPORT_DIRECTORY {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD  MajorVersion;
	WORD  MinorVersion;
	DWORD Name;
	DWORD Base;
	DWORD NumberOfFunctions;
	DWORD NumberOfNames;
	DWORD *AddressOfFunctions;
	DWORD *AddressOfNames;
	DWORD *AddressOfNameOrdinals;
}
```
![](https://i.imgur.com/M7LoOOb.png)
* **`AddressOfFunction`:** Pointer to the function array hold RVA of the function, indexed by ordinals
* **`AddressOfNames`:** Pointer to list of function names.
* **`AddressOfNameOrdinals`:** Pointer to the array of function ordinals.
* The name is located at:
```c 
(void*)AddressOfNames[i]
```
* The actual address is:
```c
(void*)AddressOfFunction[AddressOfNameOrdinals[i]]
```
* **`TimeDateStamp`:** Checked by load whether bounded imports are out of date. 
* **`Base`:** Subtracted from ordinal to get a zero-indexed offset to the arrays. By default ordinal starting by 1, but it could started from any positive integer if the programmer wants to.

#### Forward export
* Exporting a function forward to be handled by another module.
* If the RVA in `AddressOfFunctions` is a pointer, it'll point into the export section that is a pointer to string named 
`DllName.FuncName`.


#### Debug Directory
```c
typedef struct _IMAGE_DEBUG_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD  MajorVersion;
  WORD  MinorVersion;
  DWORD Type;
  DWORD SizeOfData;
  DWORD AddressOfRawData;
  DWORD PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

#define IMAGE_DEBUG_TYPE_UNKNOWN          0
#define IMAGE_DEBUG_TYPE_COFF             1
#define IMAGE_DEBUG_TYPE_CODEVIEW         2
#define IMAGE_DEBUG_TYPE_FPO              3
#define IMAGE_DEBUG_TYPE_MISC             4
#define IMAGE_DEBUG_TYPE_EXCEPTION        5
#define IMAGE_DEBUG_TYPE_FIXUP            6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8
#define IMAGE_DEBUG_TYPE_BORLAND          9
#define IMAGE_DEBUG_TYPE_RESERVED10       10
#define IMAGE_DEBUG_TYPE_CLSID            11
```
* **`TimeDateStamp`:** Yet another sanity check.
* **`Type`:** Type of debug info, defined as above. 
* **`SizeOfData`:** BJ4
* **`AddressOfRawData`:** RVA to debug info.
* **`PointerToRawData`:** File offset to the debug info.

Code view structure:
```c 
#define CV_SIGNATURE_NB10 '01BN'
#define CV_SIGNATURE_NB09 '90BN'
#define CV_SIGNATURE_RSDS 'SDSR'

typedef struct _CV_HEADER {
	DWORD dwSignature;
	DWORD dwOffset;
}CV_HEADER, *PCV_HEADER;
```
* `dwSignature`: Code view signature, equals to one of the define above
* `dwOffset`: Usually set to 0, because debug information is stored in `.pdb` file on Windows unlike ELF that stores the symbols in itself.

```c 
typedef struct _CV_INFO_PDB20 {
	CV_HEADER CvHeader;
	DWORD dwSignature;
	DWORD dwAge;
	BYTE PdbFileName[];
}CV_INFO_PDB20, *PCV_INFO_PDB20;
  
typedef struct _CV_INFO_PDB70 {
	DWORD dwHeader;
	GUID  Signature;
	DWORD dwAge;
	CHAR  PdbFileName[1];
} CV_INFO_PDB70, *PCV_INFO_PDB70;
```
* `DWORD dwSignature`: The time when debug information was created (UNIX Time)
* `GUID Signature`: A unique identifier, which changes with every rebuild of the executable and PDB file.
* `Age`: Ever-incrementing value, which is initially set to 1 and incremented every time when a part of the PDB file is updated without rewriting the whole file. 
* `PdbFileName`: Null-terminated name of the PDB file. It can also contain full or partial path to the file. 

### Relocation
```c 
// IMAGE_DIRECTORY_ENTRY_BASERELOC
struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
};

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
  //WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
```
* The directory points to an array of `_IMAGE_BASE_RELOCATION`
* **`VirtualAdress`:** Page-aligned virtual address that specified relocation target will be relative to.
* **`SizeOfBlock`:** sizeof(`IMAGE_BASE_RELOCATION`) + sizeof(`all subsequent relocation target`)
* Following `SizeOfBlock` are list number of `WORD` sized relocation targets, which length can be calculated with:
`(SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD)`
* The `value / 0x1000` is the type, rest 3 digit plus `VirtualAddress` is the RVA that needs to be relocated.(So the valid range for a relocation is 0~0xfff aka to 4095) 
```c
enum reloc_based {
    RELB_ABSOLUTE = 0,
    RELB_HIGH = 1,
    RELB_LOW = 2,
    RELB_HIGHLOW = 3,
    RELB_HIGHADJ = 4,
    RELB_MIPS_JMPADDR = 5,
    RELB_SECTION = 6,
    RELB_REL32 =  7,
    RELB_MIPS_JMPADDR16 = 9,
    RELB_IA64_IMM64 = 9,
    RELB_DIR64 =  10,
    RELB_HIGH3ADJ = 11
};
```

### Thread Local Storage (TLS)
The `VirtualAddress` in `DataDirctory[9]` points to the structure below, which has 32/64 versions.
```c
typedef struct _IMAGE_TLS_DIRECTORY32 {
  DWORD StartAddressOfRawData;
  DWORD EndAddressOfRawData;
  DWORD AddressOfIndex;
  DWORD AddressOfCallBacks;
  DWORD SizeOfZeroFill;
  DWORD Characteristics;
} IMAGE_TLS_DIRECTORY32;
typedef IMAGE_TLS_DIRECTORY32 *PIMAGE_TLS_DIRECTORY32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
  ULONGLONG StartAddressOfRawData;
  ULONGLONG EndAddressOfRawData;
  ULONGLONG AddressOfIndex;
  ULONGLONG AddressOfCallBacks;
  DWORD SizeOfZeroFill;
  DWORD Characteristics;
} IMAGE_TLS_DIRECTORY64;
typedef IMAGE_TLS_DIRECTORY64 *PIMAGE_TLS_DIRECTORY64;
```
* **`StartAddressOfRawData`** and **`EndAddressOfRawData`** is the absolute virtual address (VA) where the thread context is stored.
* **`AddressOfCallBacks`:** VA that points to an array of `PIMAGE_TLS_CALLBACK` function pointers that will be called when thread starts. **Calls before `AddressOfEntryPoint`**.

### Resources
* Generally stored in `.rsrc` section
```c 
typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    WORD    NumberOfNamedEntries;
    WORD    NumberOfIdEntries;
  //IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
```

* `IMAGE_RESOURCE_DIRECTORY_ENTRY` is followed after the `IMAGE_RESOURCE_DIRECTORY`, length is `NumberOfNamedEntries` + `NumberOfIdEntries` (Named first, then Id)

```c 
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset:31;  // least 31 bits
            DWORD NameIsString:1; // first bit
        } name;
        DWORD   Name;
        WORD    Id;
    };
    union {
        DWORD   OffsetToData;
        struct {
            DWORD   OffsetToDirectory:31;
            DWORD   DataIsDirectory:1;
        } dir;
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;
```
* If the MSB of `name` is not set, it's a `WORD Id`, otherwise second structure `dir` is used.
* If the MSB of `dir` is set, the lower 31 bits are offset to another `IMAGE_RESOURCE_DIRECTORY`, if not, it's pointed to the actual data.
* Offsets are relative to the start of `.rsrc` section

### Load Configuration
```c 
typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY32 {
  DWORD                            Size;
  DWORD                            TimeDateStamp;
  WORD                             MajorVersion;
  WORD                             MinorVersion;
  DWORD                            GlobalFlagsClear;
  DWORD                            GlobalFlagsSet;
  DWORD                            CriticalSectionDefaultTimeout;
  DWORD                            DeCommitFreeBlockThreshold;
  DWORD                            DeCommitTotalFreeThreshold;
  DWORD                            LockPrefixTable;
  DWORD                            MaximumAllocationSize;
  DWORD                            VirtualMemoryThreshold;
  DWORD                            ProcessHeapFlags;
  DWORD                            ProcessAffinityMask;
  WORD                             CSDVersion;
  WORD                             DependentLoadFlags;
  DWORD                            EditList;
  DWORD                            SecurityCookie;
  DWORD                            SEHandlerTable;
  DWORD                            SEHandlerCount;
  DWORD                            GuardCFCheckFunctionPointer;
  DWORD                            GuardCFDispatchFunctionPointer;
  DWORD                            GuardCFFunctionTable;
  DWORD                            GuardCFFunctionCount;
  DWORD                            GuardFlags;
  IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
  DWORD                            GuardAddressTakenIatEntryTable;
  DWORD                            GuardAddressTakenIatEntryCount;
  DWORD                            GuardLongJumpTargetTable;
  DWORD                            GuardLongJumpTargetCount;
  DWORD                            DynamicValueRelocTable;
  DWORD                            CHPEMetadataPointer;
  DWORD                            GuardRFFailureRoutine;
  DWORD                            GuardRFFailureRoutineFunctionPointer;
  DWORD                            DynamicValueRelocTableOffset;
  WORD                             DynamicValueRelocTableSection;
  WORD                             Reserved2;
  DWORD                            GuardRFVerifyStackPointerFunctionPointer;
  DWORD                            HotPatchTableOffset;
  DWORD                            Reserved3;
  DWORD                            EnclaveConfigurationPointer;
  DWORD                            VolatileMetadataPointer;
  DWORD                            GuardEHContinuationTable;
  DWORD                            GuardEHContinuationCount;
} IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64 {
  DWORD                            Size;
  DWORD                            TimeDateStamp;
  WORD                             MajorVersion;
  WORD                             MinorVersion;
  DWORD                            GlobalFlagsClear;
  DWORD                            GlobalFlagsSet;
  DWORD                            CriticalSectionDefaultTimeout;
  ULONGLONG                        DeCommitFreeBlockThreshold;
  ULONGLONG                        DeCommitTotalFreeThreshold;
  ULONGLONG                        LockPrefixTable;
  ULONGLONG                        MaximumAllocationSize;
  ULONGLONG                        VirtualMemoryThreshold;
  ULONGLONG                        ProcessAffinityMask;
  DWORD                            ProcessHeapFlags;
  WORD                             CSDVersion;
  WORD                             DependentLoadFlags;
  ULONGLONG                        EditList;
  ULONGLONG                        SecurityCookie;
  ULONGLONG                        SEHandlerTable;
  ULONGLONG                        SEHandlerCount;
  ULONGLONG                        GuardCFCheckFunctionPointer;
  ULONGLONG                        GuardCFDispatchFunctionPointer;
  ULONGLONG                        GuardCFFunctionTable;
  ULONGLONG                        GuardCFFunctionCount;
  DWORD                            GuardFlags;
  IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
  ULONGLONG                        GuardAddressTakenIatEntryTable;
  ULONGLONG                        GuardAddressTakenIatEntryCount;
  ULONGLONG                        GuardLongJumpTargetTable;
  ULONGLONG                        GuardLongJumpTargetCount;
  ULONGLONG                        DynamicValueRelocTable;
  ULONGLONG                        CHPEMetadataPointer;
  ULONGLONG                        GuardRFFailureRoutine;
  ULONGLONG                        GuardRFFailureRoutineFunctionPointer;
  DWORD                            DynamicValueRelocTableOffset;
  WORD                             DynamicValueRelocTableSection;
  WORD                             Reserved2;
  ULONGLONG                        GuardRFVerifyStackPointerFunctionPointer;
  DWORD                            HotPatchTableOffset;
  DWORD                            Reserved3;
  ULONGLONG                        EnclaveConfigurationPointer;
  ULONGLONG                        VolatileMetadataPointer;
  ULONGLONG                        GuardEHContinuationTable;
  ULONGLONG                        GuardEHContinuationCount;
} IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;
```
* `SecurityCookie`: A VA that points to the location where the stack cookie used with the `/GS` flag will be.
* `SEHandlerTable`: is a VA which points to a table of RVAs which specify the only exception handlers which are valid for use with Structure Exception Handler (SEH). The placement of the pointers to these handlers is caused by the `/SAFESEH` linker options.
* `SEHandlerCount`: length of the array `SEHandlerTable`pointed.

### Security Directory (Digital Signature)
```c
// IMAGE_DIRECTORY_ENTRY_SECURITY

struct _IMAGE_DAT_DIRECTORY {
     DWORD VirtualAddress;
     DWORD Size;
}
```
* Points to the digital certificate if presents.

### PE Loader Steps
1. Creates a virtual address space for the process
2. Reads the executable file
3. Trying to load the file into its preferred address (`ImageNtHeader.OptitonalHeader.ImageBase`)
    * Loads to another address if failed, and the image needs to be relocated.
    * If the image does not contain the relocation information (i.e. `IMAGE_FILE_RELOCS_STRIPPED` flag is set), this PE cannot be load unless it's at preferred address.
4. Calculates the VA of section table (section headers) then maps onto memory (`VA = ImageBase + RVA`)
5. Perform base relocation if `ImageBase` does not loaded in preferred address.
6. Resolve the IAT and maps all required DLLs into address space.
7. Resolve export of DLLs and fixes IAT to pointed at actual imported function address.
8. Execute TLS callbacks
9. Calls `AddressOfEntryPoint`

## ELF
WIP