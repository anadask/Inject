// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"


#include"ReflectiveDllInjection.h"
#define DLL_QUERY_HMODULE		6

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_QUERY_HMODULE:
	{
		if (lpReserved != NULL)
		{
			
		}
			
		break;
	}
		
	case DLL_PROCESS_ATTACH:
	{
		
		MessageBoxA(NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK);
		break;
	
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

