// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
LRESULT CALLBACK TestRun(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK TestRun(int nCode,WPARAM wParam,LPARAM lParam)
{
	MessageBoxA(NULL,"Successful", NULL, NULL);
	return NULL;
}

