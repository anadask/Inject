// InjectByAPC.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#define _WIN32_WINNT 0x0400
#define WIN32_LEAN_AND_MEAN   // 从 Windows 头中排除极少使用的资料
#include<Windows.h>
#include <iostream>
#include <Tlhelp32.h>
using namespace std;

typedef struct _THREADID_LIST_
{
	DWORD ThreadID;
	_THREADID_LIST_ *pNext;
}THREADIDLIST,*PTHREADIDLIST;
DWORD GetProcessID(const TCHAR* szProcessName);
PTHREADIDLIST InsertTid(PTHREADIDLIST ThreadIDList, DWORD ThreadId);
int EnumThreadID(DWORD ProcessID, PTHREADIDLIST ThreadIDList);
DWORD EnumThread(HANDLE ProcessHandle, PTHREADIDLIST ThreadIDList);


int main()
{
	
	PTHREADIDLIST ThreadIDList = (PTHREADIDLIST)malloc(sizeof(THREADIDLIST));

	if (ThreadIDList == NULL)
	{
		return 0;
	}
	RtlZeroMemory(ThreadIDList, sizeof(THREADIDLIST));

	DWORD ProcessID = 0;
	if ((ProcessID = GetProcessID("explorer.exe")) == 0xFFFFFFFF)
	{
		printf("进程ID获取失败!\n");
		return 0;
	}
	
	EnumThreadID(ProcessID, ThreadIDList);

	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

	if (ProcessHandle == NULL)
	{
		return 0;
	}
	EnumThread(ProcessHandle, ThreadIDList);
	getchar();
	getchar();
    return 0;
}

DWORD GetProcessID(const TCHAR* szProcessName)
{
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	if (!Process32First(hSnapshot, &pe32))
	{
		return -1;
	}

	do
	{
		if (!_strnicmp(szProcessName, pe32.szExeFile, strlen(szProcessName)))
		{
			printf("%s的PID是:%d\n", pe32.szExeFile, pe32.th32ProcessID);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &pe32));

	return -1;
}
// 枚举线程ID
int EnumThreadID(DWORD ProcessID, PTHREADIDLIST ThreadIDList)
{
	int i = 0;

	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ProcessID);

	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		if (Thread32First(hSnapshot, &te32))
		{
			do
			{
				if (te32.th32OwnerProcessID == ProcessID)
				{
					if (ThreadIDList->ThreadID == 0)
					{
						ThreadIDList->ThreadID = te32.th32ThreadID;
					}
					else
					{
						if (NULL == InsertTid(ThreadIDList, te32.th32ThreadID))
						{
							printf("插入失败!\n");
							return 0;
						}
					}

				}
			} while (Thread32Next(hSnapshot, &te32));
		}
	}
	return 1;
}
PTHREADIDLIST InsertTid(PTHREADIDLIST ThreadIDList, DWORD ThreadId)
{
	PTHREADIDLIST pCurrent = NULL;
	PTHREADIDLIST pNewMember = NULL;

	if (ThreadIDList == NULL)
	{
		return NULL;
	}
	pCurrent = ThreadIDList;

	while (pCurrent != NULL)
	{

		if (pCurrent->pNext == NULL)
		{
			//
			// 定位到链表最后一个元素
			//
			pNewMember = (PTHREADIDLIST )malloc(sizeof(THREADIDLIST));

			if (pNewMember != NULL)
			{
				pNewMember->ThreadID = ThreadId;
				pNewMember->pNext = NULL;
				pCurrent->pNext = pNewMember;
				return pNewMember;
			}
			else
			{
				return NULL;
			}
		}
		pCurrent = pCurrent->pNext;
	}

	return NULL;
}

DWORD EnumThread(HANDLE ProcessHandle, PTHREADIDLIST ThreadIDList)
{
	//默认第一个？
	PTHREADIDLIST CurrentThreadID = ThreadIDList;

	const char szInjectModName[] = "J:\\注入\\InjectByAPC\\x64\\Debug\\DLL.dll";
	DWORD Length = strlen(szInjectModName);

	PVOID Address = VirtualAllocEx(ProcessHandle,
		NULL, Length, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

	if (Address != NULL)
	{
		SIZE_T ReturnLength;
		//
		//将动态库的地址写进去
		//
		if (WriteProcessMemory(ProcessHandle, Address, (LPVOID)szInjectModName, Length, &ReturnLength))
		{
			while (CurrentThreadID)
			{
				HANDLE ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, CurrentThreadID->ThreadID);

				if (ThreadHandle != NULL)
				{
					//
					// 注入DLL到指定进程
					//Address LoadLibraryA 参数
					//
					QueueUserAPC((PAPCFUNC)LoadLibraryA, ThreadHandle, (ULONG_PTR)Address);
				}

				printf("TID:%d\n", CurrentThreadID->ThreadID);
				CurrentThreadID = CurrentThreadID->pNext;
			}
		}
	}
	return 0;
}