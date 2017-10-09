// InjectByCreateRemotThread.cpp : 定义控制台应用程序的入口点。
//

#include<Windows.h>
#include<iostream>

using namespace std;

int main()
{

	DWORD dwProcessID = 0;
	cin >> dwProcessID;

	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);

	if (ProcessHandle == NULL)
	{
		cout << "OpenProcess Error" << endl;
		return 0;
	}

	char* szDllFullPath = "J:\\注入\\InjectByCreateRemotThread\Debug\\Dll.dll";

	LPVOID Address = VirtualAllocEx(ProcessHandle, NULL, strlen(szDllFullPath)+1,MEM_COMMIT| MEM_RESERVE, PAGE_READWRITE);
	int a = GetLastError();
	if (Address == NULL)
	{
		cout << "VirtualAllocEx Error" << endl;
		return 0;
	}

	DWORD dwOldProtect = 0;
	

	if (!WriteProcessMemory(ProcessHandle, Address, szDllFullPath, strlen(szDllFullPath), 0))
	{
		a = GetLastError();
	}
	


	HMODULE ModuleHandle = LoadLibraryA("Kernel32.dll");
	if (ModuleHandle == NULL)
	{
		cout << "LoadLibraryA Error" << endl;
		return 0;
	}
	
	SIZE_T FunctionAddress = (SIZE_T)GetProcAddress(ModuleHandle, "LoadLibraryA");
	if (FunctionAddress == NULL)
	{
		cout << "GetProcAddress Error" << endl;
		return 0;
	}
	
	HANDLE ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, NULL, 
		(LPTHREAD_START_ROUTINE)FunctionAddress, Address, 0, NULL);

	a = GetLastError();

	WaitForSingleObject(ThreadHandle, INFINITE);



    return 0;
}

