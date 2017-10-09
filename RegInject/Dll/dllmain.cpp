// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include<Windows.h>

DWORD WINAPI ThreadCallback(LPVOID lParam);
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		HANDLE ThreadHandle = 
			CreateThread(0, 0,ThreadCallback, NULL, 0, NULL);
		
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
DWORD WINAPI ThreadCallback(LPVOID lParam)
{
	MessageBoxA(NULL, "Inject", "Suceessful", MB_OK);
	return 0;
}

