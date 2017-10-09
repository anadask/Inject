
#include "stdafx.h"
#include"ReflectiveDllInjection.h"

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

//���ص�ǰ���ú������صĵ�ַ����������һ��ָ���ַ
#pragma intrinsic( _ReturnAddress )
__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID)
{
/*	//��Ҫ�ĺ���
	LOADLIBRARYA pLoadLibrary = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;


	ULONG_PTR LibraryAddress     = 0;
	ULONG_PTR NtHeader           = 0;
	ULONG_PTR PEBAddress         = 0;
	ULONG_PTR LdrAddress         = 0;
	ULONG_PTR ModulelBaseAddress = 0;
	ULONG_PTR ExportRVA          = 0;
	ULONG_PTR ExportTable        = 0;
	ULONG_PTR v1                 = 0;
	ULONG_PTR v2                 = 0;
	ULONG_PTR v3                 = 0;
	USHORT Count                 = 0;
	ULONG_PTR NameOrdinals       = 0;
	ULONG_PTR NameArray          = 0;
	
	DWORD HashValue              = 0;
	ULONG_PTR AddressArray       = 0;

	LibraryAddress = caller();
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)LibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			NtHeader = ((PIMAGE_DOS_HEADER)LibraryAddress)->e_lfanew;

			if (NtHeader >= sizeof(IMAGE_DOS_HEADER) && NtHeader < 1024)
			{
				NtHeader += LibraryAddress;
				if (((PIMAGE_NT_HEADERS)NtHeader)->Signature == IMAGE_NT_SIGNATURE)
				{
					break;
				}
			}
		}
		LibraryAddress--;
	}
//�õ�PEB
#ifdef _WIN64
	PEBAddress = __readgsqword(0x60);
#else 
	PEBAddress = __readfsdword(0x30);
#endif

	LdrAddress = (ULONG_PTR)((_PPEB)PEBAddress)->pLdr;
	v1        = (ULONG_PTR)((PPEB_LDR_DATA)LdrAddress)->InMemoryOrderModuleList.Flink;

	while (v1)
	{
		//�õ���һģ������Ƶ�ַ
		v2    = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)v1)->BaseDllName.Buffer;
		Count = ((PLDR_DATA_TABLE_ENTRY)v1)->BaseDllName.Length;

		v3 = 0;
		do
		{
			v3 = ror((DWORD)v3);
			if (*((BYTE *)v2) >= 'a')
			{
				v3 += *((BYTE*)v2) - 0x20;

			}
			else
			{
				v3 += *((BYTE*)v2);
			}
			v2++;
		} while (--Count);

		if ((DWORD)v3 == KERNEL32DLL_HASH)
		{
			ModulelBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)v1)->DllBase;
			NtHeader = ModulelBaseAddress + ((PIMAGE_DOS_HEADER)ModulelBaseAddress)->e_lfanew;

			ExportRVA   = (ULONG_PTR)&((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			
			ExportTable = (ModulelBaseAddress + ((PIMAGE_DATA_DIRECTORY)ExportRVA)->VirtualAddress);

			
			NameArray   = (ModulelBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfNames);

		
			NameOrdinals = (ModulelBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfNameOrdinals);

			Count        = 3;
			
			while (Count > 0)
			{
				// compute the hash values for this function name
				HashValue = hash((char *)(ModulelBaseAddress + (*(DWORD*)(NameArray))));
				if (HashValue == LOADLIBRARYA_HASH || HashValue == GETPROCADDRESS_HASH || HashValue == VIRTUALALLOC_HASH)
				{
					AddressArray = (ModulelBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					AddressArray += (DEREF_16(NameOrdinals)) * sizeof(DWORD);

					// store this functions VA
					if (HashValue == LOADLIBRARYA_HASH)
					{
						pLoadLibrary = (LOADLIBRARYA)(ModulelBaseAddress + DEREF_32(AddressArray));
					}
						
					else if (HashValue == GETPROCADDRESS_HASH)
					{
						pGetProcAddress = (GETPROCADDRESS)(ModulelBaseAddress + DEREF_32(AddressArray));
					}
						
					else if (HashValue == VIRTUALALLOC_HASH)
					{
						pVirtualAlloc = (VIRTUALALLOC)(ModulelBaseAddress + DEREF_32(AddressArray));
					}
						

					// decrement our counter
					Count--;
				}
				
				NameArray += sizeof(DWORD);

				NameOrdinals += sizeof(WORD);
			}
		}
		else if ((DWORD)v3 == NTDLLDLL_HASH)
		{
			// get this modules base address
			ModulelBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)v1)->DllBase;

			// get the VA of the modules NT Header
			NtHeader = ModulelBaseAddress + ((PIMAGE_DOS_HEADER)ModulelBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			ExportRVA = (ULONG_PTR)&((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			ExportTable = (ModulelBaseAddress + ((PIMAGE_DATA_DIRECTORY)ExportRVA)->VirtualAddress);

			// get the VA for the array of name pointers
			NameArray = (ModulelBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfNames);

			// get the VA for the array of name ordinals
			NameOrdinals = (ModulelBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfNameOrdinals);

			Count = 1;

			// loop while we still have imports to find
			while (Count > 0)
			{
				// compute the hash values for this function name
				HashValue = hash((char *)(ModulelBaseAddress + DEREF_32(NameArray)));

				// if we have found a function we want we get its virtual address
				if (HashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
				{
					// get the VA for the array of addresses
					AddressArray = (ModulelBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					AddressArray += (DEREF_16(NameOrdinals)) * sizeof(DWORD);

					// store this functions VA
					if (HashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
						pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(ModulelBaseAddress + (*(DWORD*)(AddressArray)));

					// decrement our counter
					Count--;
				}

				// get the next exported function name
				NameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				NameOrdinals += sizeof(WORD);
			}
		}
		// we stop searching when we have found everything we need.
		if (pLoadLibrary && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
		{
			break;
		}
			

		// get the next entry
		v1 = DEREF(v1);

	}
	
	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	NtHeader = LibraryAddress + ((PIMAGE_DOS_HEADER)LibraryAddress)->e_lfanew;

	ULONG_PTR Address = 0;
	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	Address = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	v1 = ((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.SizeOfHeaders;
	v2 = LibraryAddress;
	v3 = Address;
	//ӳ��PE�ļ� DOSͷ�� NTͷ�� ��������ܴ�С
	while (v1--)
	{
		*(BYTE *)v3++ = *(BYTE *)v2++;
	}
	
	//ӳ��PE�ļ��Ŀ��
	v1 = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader + ((PIMAGE_NT_HEADERS)NtHeader)->FileHeader.SizeOfOptionalHeader);
	ULONG_PTR SectionNumber = 0;
	ULONG_PTR v4 = 0;
	SectionNumber = ((PIMAGE_NT_HEADERS)NtHeader)->FileHeader.NumberOfSections;
	while (SectionNumber--)
	{
		// uiValueB is the VA for this section
		v2 = (Address + ((PIMAGE_SECTION_HEADER)v1)->VirtualAddress);

		// uiValueC if the VA for this sections data
		v3 = (LibraryAddress + ((PIMAGE_SECTION_HEADER)v1)->PointerToRawData);

		// copy the section over
		v4 = ((PIMAGE_SECTION_HEADER)v1)->SizeOfRawData;

		while (v4--)
		{
			*(BYTE *)v2++ = *(BYTE *)v3++;
		}
			

		// get the VA of the next section
		v1 += sizeof(IMAGE_SECTION_HEADER);
	}
	
	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	v2 = (ULONG_PTR)&((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	v3 = (Address + ((PIMAGE_DATA_DIRECTORY)v2)->VirtualAddress);

	// itterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)v3)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		LibraryAddress = (ULONG_PTR)pLoadLibrary((LPCSTR)(Address + ((PIMAGE_IMPORT_DESCRIPTOR)v3)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		v4 = (Address + ((PIMAGE_IMPORT_DESCRIPTOR)v3)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		v1 = (Address + ((PIMAGE_IMPORT_DESCRIPTOR)v3)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(v1))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (v4 && ((PIMAGE_THUNK_DATA)v4)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				NtHeader = LibraryAddress + ((PIMAGE_DOS_HEADER)LibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				ExportRVA = (ULONG_PTR)&((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				ExportTable = (LibraryAddress + ((PIMAGE_DATA_DIRECTORY)ExportRVA)->VirtualAddress);

				// get the VA for the array of addresses
				AddressArray = (LibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				AddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)v4)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)ExportTable)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(v1) = (LibraryAddress + DEREF_32(AddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				v2 = (Address + DEREF(v1));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(v1) = (ULONG_PTR)pGetProcAddress((HMODULE)LibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)v2)->Name);
			}
			// get the next imported function
			v1 += sizeof(ULONG_PTR);
			if (v4)
			{
				v4 += sizeof(ULONG_PTR);
			}
				
		}

		// get the next import
		v3 += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	
	// STEP 5: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	LibraryAddress = Address - ((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	v2 = (ULONG_PTR)&((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)v2)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		v3 = (Address + ((PIMAGE_DATA_DIRECTORY)v2)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)v3)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			v1 = (Address + ((PIMAGE_BASE_RELOCATION)v3)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			v2 = (((PIMAGE_BASE_RELOCATION)v3)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			v4 = v3 + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (v2--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)v4)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR *)(v1 + ((PIMAGE_RELOC)v4)->offset) += LibraryAddress;
				else if (((PIMAGE_RELOC)v4)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD *)(v1 + ((PIMAGE_RELOC)v4)->offset) += (DWORD)LibraryAddress;

				else if (((PIMAGE_RELOC)v4)->type == IMAGE_REL_BASED_HIGH)
					*(WORD *)(v1 + ((PIMAGE_RELOC)v4)->offset) += HIWORD(LibraryAddress);
				else if (((PIMAGE_RELOC)v4)->type == IMAGE_REL_BASED_LOW)
					*(WORD *)(v1 + ((PIMAGE_RELOC)v4)->offset) += LOWORD(LibraryAddress);

				// get the next entry in the current relocation block
				v4 += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			v3 = v3 + ((PIMAGE_BASE_RELOCATION)v3)->SizeOfBlock;
		}
	}
	
	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	v1 = (Address + ((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
#else
	// if we are injecting an DLL via a stub we call DllMain with no parameter
	((DLLMAIN)v1)((HINSTANCE)Address, DLL_PROCESS_ATTACH, NULL);
#endif

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return v1;*/
	// the functions we need
LOADLIBRARYA pLoadLibraryA = NULL;
GETPROCADDRESS pGetProcAddress = NULL;
VIRTUALALLOC pVirtualAlloc = NULL;
NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

USHORT usCounter;

// the initial location of this image in memory
ULONG_PTR uiLibraryAddress;
// the kernels base address and later this images newly loaded base address
ULONG_PTR uiBaseAddress;

// variables for processing the kernels export table
ULONG_PTR uiAddressArray;
ULONG_PTR uiNameArray;
ULONG_PTR uiExportDir;
ULONG_PTR uiNameOrdinals;
DWORD dwHashValue;

// variables for loading this image
ULONG_PTR uiHeaderValue;
ULONG_PTR uiValueA;
ULONG_PTR uiValueB;
ULONG_PTR uiValueC;
ULONG_PTR uiValueD;
ULONG_PTR uiValueE;

// STEP 0: calculate our images current base address

// we will start searching backwards from our callers return address.
uiLibraryAddress = caller();

// loop through memory backwards searching for our images base address
// we dont need SEH style search as we shouldnt generate any access violations with this
while (TRUE)
{
	if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
	{
		uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
		// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
		// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
		if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
		{
			uiHeaderValue += uiLibraryAddress;
			// break if we have found a valid MZ/PE header
			if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
				break;
		}
	}
	uiLibraryAddress--;
}

// STEP 1: process the kernels exports for the functions our loader needs...

// get the Process Enviroment Block
#ifdef _WIN64
uiBaseAddress = __readgsqword(0x60);
#else
#ifdef WIN_X86
uiBaseAddress = __readfsdword(0x30);
#else WIN_ARM
uiBaseAddress = *(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#endif
#endif

// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

// get the first entry of the InMemoryOrder module list
uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
while (uiValueA)
{
	// get pointer to current modules name (unicode string)
	uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Buffer;
	// set bCounter to the length for the loop
	usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
	// clear uiValueC which will store the hash of the module name
	uiValueC = 0;

	// compute the hash of the module name...
	do
	{
		uiValueC = ror((DWORD)uiValueC);
		// normalize to uppercase if the madule name is in lowercase
		if (*((BYTE *)uiValueB) >= 'a')
			uiValueC += *((BYTE *)uiValueB) - 0x20;
		else
			uiValueC += *((BYTE *)uiValueB);
		uiValueB++;
	} while (--usCounter);

	// compare the hash with that of kernel32.dll
	if ((DWORD)uiValueC == KERNEL32DLL_HASH)
	{
		// get this modules base address
		uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

		// get the VA of the modules NT Header
		uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

		// uiNameArray = the address of the modules export directory entry
		uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		// get the VA of the export directory
		uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

		// get the VA for the array of name pointers
		uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

		// get the VA for the array of name ordinals
		uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

		usCounter = 3;

		// loop while we still have imports to find
		while (usCounter > 0)
		{
			// compute the hash values for this function name
			dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

			// if we have found a function we want we get its virtual address
			if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH)
			{
				// get the VA for the array of addresses
				uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use this functions name ordinal as an index into the array of name pointers
				uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

				// store this functions VA
				if (dwHashValue == LOADLIBRARYA_HASH)
					pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
				else if (dwHashValue == GETPROCADDRESS_HASH)
					pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
				else if (dwHashValue == VIRTUALALLOC_HASH)
					pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));

				// decrement our counter
				usCounter--;
			}

			// get the next exported function name
			uiNameArray += sizeof(DWORD);

			// get the next exported function name ordinal
			uiNameOrdinals += sizeof(WORD);
		}
	}
	else if ((DWORD)uiValueC == NTDLLDLL_HASH)
	{
		// get this modules base address
		uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

		// get the VA of the modules NT Header
		uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

		// uiNameArray = the address of the modules export directory entry
		uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		// get the VA of the export directory
		uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

		// get the VA for the array of name pointers
		uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

		// get the VA for the array of name ordinals
		uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

		usCounter = 1;

		// loop while we still have imports to find
		while (usCounter > 0)
		{
			// compute the hash values for this function name
			dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

			// if we have found a function we want we get its virtual address
			if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
			{
				// get the VA for the array of addresses
				uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use this functions name ordinal as an index into the array of name pointers
				uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

				// store this functions VA
				if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
					pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uiBaseAddress + DEREF_32(uiAddressArray));

				// decrement our counter
				usCounter--;
			}

			// get the next exported function name
			uiNameArray += sizeof(DWORD);

			// get the next exported function name ordinal
			uiNameOrdinals += sizeof(WORD);
		}
	}

	// we stop searching when we have found everything we need.
	if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
		break;

	// get the next entry
	uiValueA = DEREF(uiValueA);
}

// STEP 2: load our image into a new permanent location in memory...

// get the VA of the NT Header for the PE to be loaded
uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// we must now copy over the headers
uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
uiValueB = uiLibraryAddress;
uiValueC = uiBaseAddress;

while (uiValueA--)
*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

// STEP 3: load in all of our sections...

// uiValueA = the VA of the first section
uiValueA = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

// itterate through all sections, loading them into memory.
uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
while (uiValueE--)
{
	// uiValueB is the VA for this section
	uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

	// uiValueC if the VA for this sections data
	uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

	// copy the section over
	uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

	while (uiValueD--)
		*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

	// get the VA of the next section
	uiValueA += sizeof(IMAGE_SECTION_HEADER);
}

// STEP 4: process our images import table...

// uiValueB = the address of the import directory
uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

// we assume their is an import table to process
// uiValueC is the first entry in the import table
uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

// itterate through all imports
while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
{
	// use LoadLibraryA to load the imported module into memory
	uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

	// uiValueD = VA of the OriginalFirstThunk
	uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

	// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
	uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

	// itterate through all imported functions, importing by ordinal if no name present
	while (DEREF(uiValueA))
	{
		// sanity check uiValueD as some compilers only import by FirstThunk
		if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
		{
			// get the VA of the modules NT Header
			uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of addresses
			uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

			// patch in the address for this imported function
			DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			// get the VA of this functions import by name struct
			uiValueB = (uiBaseAddress + DEREF(uiValueA));

			// use GetProcAddress and patch in the address for this imported function
			DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
		}
		// get the next imported function
		uiValueA += sizeof(ULONG_PTR);
		if (uiValueD)
			uiValueD += sizeof(ULONG_PTR);
	}

	// get the next import
	uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
}

// STEP 5: process all of our images relocations...

// calculate the base address delta and perform relocations (even if we load at desired image base)
uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

// uiValueB = the address of the relocation directory
uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

// check if their are any relocations present
if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
{
	// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// and we itterate through all entries...
	while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
	{
		// uiValueA = the VA for this relocation block
		uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

		// uiValueB = number of entries in this relocation block
		uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

		// uiValueD is now the first entry in the current relocation block
		uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

		// we itterate through all the entries in the current block...
		while (uiValueB--)
		{
			// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
			// we dont use a switch statement to avoid the compiler building a jump table
			// which would not be very position independent!
			if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
				*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
			else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
				*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
#ifdef WIN_ARM
			// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
			else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_ARM_MOV32T)
			{
				register DWORD dwInstruction;
				register DWORD dwAddress;
				register WORD wImm;
				// get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
				dwInstruction = *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD));
				// flip the words to get the instruction as expected
				dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				// sanity chack we are processing a MOV instruction...
				if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT)
				{
					// pull out the encoded 16bit value (the high portion of the address-to-relocate)
					wImm = (WORD)(dwInstruction & 0x000000FF);
					wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
					wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
					wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
					// apply the relocation to the target address
					dwAddress = ((WORD)HIWORD(uiLibraryAddress) + wImm) & 0xFFFF;
					// now create a new instruction with the same opcode and register param.
					dwInstruction = (DWORD)(dwInstruction & ARM_MOV_MASK2);
					// patch in the relocated address...
					dwInstruction |= (DWORD)(dwAddress & 0x00FF);
					dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
					dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
					dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
					// now flip the instructions words and patch back into the code...
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				}
			}
#endif
			else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
				*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
			else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
				*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

			// get the next entry in the current relocation block
			uiValueD += sizeof(IMAGE_RELOC);
		}

		// get the next entry in the relocation directory
		uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
	}
}

// STEP 6: call our images entry point

// uiValueA = the VA of our newly loaded DLL/EXE's entry point
uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

// call our respective entry point, fudging our hInstance value
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
#else
// if we are injecting an DLL via a stub we call DllMain with no parameter
((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
#endif

// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
return uiValueA;
}