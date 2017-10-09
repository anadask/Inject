// InjectDllBySetWindowsHookEx.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <Windows.h>
HHOOK hHook;
int SetHook(char* dllName, char* FunctionName, DWORD ThreadId)
{
	HMODULE DllModule;
	FARPROC dllFunction;
	DllModule = LoadLibraryA(dllName);
	dllFunction = GetProcAddress(DllModule,FunctionName);
	int a = GetLastError();
	printf("DLL %d Func %d\n", DllModule, dllFunction);

	hHook = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)dllFunction,
		DllModule, ThreadId);


	if (hHook == NULL)
	{
		return GetLastError();
	}
	return 0;


}

int RemoveHook()
{
	if (UnhookWindowsHookEx(hHook) == 0)
	{
		return GetLastError();
	}
	return 0;
}
int main()
{
	//����һ�����Խ���
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	BOOL bok = CreateProcessA("J:\\ע��\\InjectDllBySetWindowsHookEx\\Debug\\test.exe",
		NULL
		, NULL, NULL, NULL, 
		CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	
	ResumeThread(pi.hThread);

	if (SetHook("DLL.dll", "TestRun", 
		(DWORD)pi.dwThreadId) != 0)
	{
		printf("Error Hook! %d", GetLastError());
		return 0;
	}
	printf("Hooked\n");

	ResumeThread(pi.hThread);
	if (RemoveHook() != 0)
	{
		printf("Error Remove Hook!");
		return 0;
	}
    return 0;
}

