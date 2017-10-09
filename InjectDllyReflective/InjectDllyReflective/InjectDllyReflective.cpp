// InjectDllyReflective.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
using namespace std;
#define DLL_QUERY_HMODULE		6


typedef ULONG_PTR(WINAPI * REFLECTIVELOADER)(VOID);
typedef BOOL(WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

HANDLE LoadRemoteLibraryR(HANDLE TargetProcessHandle, LPVOID BufferData, 
	DWORD BufferLength, LPVOID lpParameter);
DWORD GetReflectiveLoaderOffset(LPVOID ReflectiveDllBuffer);
DWORD Rva2Offset(DWORD Rva, UINT_PTR BaseAddress);
int main()
{
	DWORD TargetProcessID = 0;
	HANDLE FileHandle = NULL;
	HANDLE TokenHandle = NULL;
	HANDLE TargetProcessHandle = NULL;
	HANDLE ModuleHandle = NULL;
	DWORD FileLength = 0;
	LPVOID BufferData = NULL;
	DWORD ReturnLength = 0;
#ifdef WIN_X64
	char * DllFile = "Dll.dll";
#else
	char * DllFile = "J:\\注入\\InjectDllyReflective\\x64\\Debug\\Dll.dll";
#endif
	do 
	{
		cin >> TargetProcessID;
		FileHandle = CreateFileA(DllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (FileHandle == INVALID_HANDLE_VALUE)
		{
			printf("Failed to open the DLL file\r\n");
			return  0;
		}
		FileLength = GetFileSize(FileHandle, NULL);
		if (FileLength == INVALID_FILE_SIZE || FileLength == 0)
		{
			printf("Failed to get the DLL file ");
			return 0;
		}

		BufferData = HeapAlloc(GetProcessHeap(), 0, FileLength);
		if(!BufferData)
		{
			printf("Failed to get the DLL file size");
			return 0;
		}
		if (ReadFile(FileHandle, BufferData, FileLength, &ReturnLength, NULL) == FALSE)
		{
			HeapFree(GetProcessHeap(), 0, BufferData);
			int a = GetLastError();
			printf("Failed To Alloc a Buffer");
			return 0;
		}
		//提权
		TOKEN_PRIVILEGES TokenPrivileges = { 0 };
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
		{
			TokenPrivileges.PrivilegeCount = 1;
			TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;


			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &TokenPrivileges.Privileges[0].Luid))
			{
				AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, 0, NULL, NULL);
			}
			CloseHandle(TokenHandle);
			

		}

		TargetProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, TargetProcessID);
		if (TargetProcessHandle == NULL)
		{
			printf("Failed to open the target process");
			HeapFree(GetProcessHeap(), 0, BufferData);
			return 0;
		}
		ModuleHandle = LoadRemoteLibraryR(TargetProcessHandle, BufferData, FileLength, NULL);

		if (!ModuleHandle)
		{
			printf("Failed to inject the DLL");
			HeapFree(GetProcessHeap(), 0, BufferData);
			return 0;
		}
		printf("[+] Injected the '%s' DLL into process %d.", DllFile, TargetProcessID);

		WaitForSingleObject(ModuleHandle, -1);
	} while (0);

	if (BufferData)
	{
		HeapFree(GetProcessHeap(), 0, BufferData);
	}
	if (TargetProcessHandle)
	{
		CloseHandle(TargetProcessHandle);
	}

    return 0;
}

HANDLE LoadRemoteLibraryR(HANDLE TargetProcessHandle, LPVOID BufferData, DWORD BufferLength, LPVOID lpParameter)
{
	HANDLE ThreadHandle = NULL;
	DWORD ThreadID = 0;
	DWORD ReflectiveLoaderOffset = 0;
	REFLECTIVELOADER ReflectiveLoader = NULL;
	DWORD OldProtect = 0;
	HMODULE ResultHandle = NULL;
	DLLMAIN pDllMain = NULL;
	__try
	{
		if (!TargetProcessHandle || !BufferData || !BufferLength)
		{
			return NULL;
		}
		//得到导出函数地址偏移
		ReflectiveLoaderOffset = GetReflectiveLoaderOffset(BufferData);
		if (ReflectiveLoaderOffset != 0)
		{
			//函数地址
			ReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)BufferData + ReflectiveLoaderOffset);
			if (VirtualProtect(BufferData, BufferLength, PAGE_EXECUTE_READWRITE, &OldProtect))
			{
				pDllMain = (DLLMAIN)ReflectiveLoader();
				if (pDllMain != NULL)
				{
					if (!pDllMain(NULL, DLL_QUERY_HMODULE, &ResultHandle))
					{
						ResultHandle = NULL;
					}
				}
				VirtualProtect(BufferData, BufferLength, OldProtect, &OldProtect);
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ThreadHandle = NULL;
	}
	return ResultHandle;
}
DWORD GetReflectiveLoaderOffset(LPVOID ReflectiveDllBuffer)
{
	UINT_PTR BaseAddress = 0;
	UINT_PTR NtHeader = 0;
	UINT_PTR ExportRVA = 0;
	UINT_PTR ExportTable = 0;
	UINT_PTR NameArray = 0;
	UINT_PTR AddressArray = 0;
	UINT_PTR NameOrdinals = 0;
	DWORD NumberOfFunctions = 0;


#ifdef _WIN64                  //没什么用   检测而已
	DWORD CompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD CompiledArch = 1;
#endif
	//Dll的基地址
	BaseAddress = (UINT_PTR)ReflectiveDllBuffer;

	NtHeader = BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew;
	//
	//32位
	//
	if (((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.Magic == 0x010B)
	{
		if (CompiledArch != 1)
		{
			return 0;
		}
	}
	else if (((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.Magic == 0x020B)
	{

		if (CompiledArch != 2)
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
	ExportRVA = (UINT_PTR)&((PIMAGE_NT_HEADERS)NtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	//得到导出表x
	ExportTable = BaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)ExportRVA)->VirtualAddress, BaseAddress);

	NameArray = BaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfNames, BaseAddress);

	AddressArray = BaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfFunctions, BaseAddress);

	NameOrdinals = BaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfNameOrdinals, BaseAddress);

	NumberOfFunctions = ((PIMAGE_EXPORT_DIRECTORY)ExportTable)->NumberOfNames;

	while (NumberOfFunctions--)
	{
		char* FunctionName = (char*)(BaseAddress + Rva2Offset(*(DWORD*)(NameArray), BaseAddress));

		if (strstr(FunctionName, "ReflectiveLoader") != NULL)
		{
			AddressArray = BaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)ExportTable)->AddressOfFunctions, BaseAddress);

			AddressArray += (*(WORD*)(NameOrdinals)) * sizeof(DWORD);
			return Rva2Offset(*(DWORD*)AddressArray, BaseAddress);

		}
		NameArray += sizeof(DWORD);
		NameOrdinals += sizeof(WORD);
	}
	return 0;
}

DWORD Rva2Offset(DWORD Rva, UINT_PTR BaseAddress)
{
	
	PIMAGE_SECTION_HEADER SectionHeader = NULL;
	PIMAGE_NT_HEADERS NtHeader = NULL;
	NtHeader = (PIMAGE_NT_HEADERS)(BaseAddress +
		((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
	//得到区块表的数据
	SectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&NtHeader->OptionalHeader) + NtHeader->FileHeader.SizeOfOptionalHeader);
	if (Rva < SectionHeader[0].PointerToRawData)  //PointerToRawData该块在磁盘文件的偏移
	{
		return Rva;
	}
	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	{
		//VirtualAddress 区块的RVA地址  SizeOfRawData在文件中对齐后的尺寸
		if (Rva >= SectionHeader[i].VirtualAddress && Rva < (SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData))
		{
			return (Rva - SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData);
		}
	}
	return 0;
}