// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"
LRESULT CALLBACK TestRun(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK TestRun(int nCode,WPARAM wParam,LPARAM lParam)
{
	MessageBoxA(NULL,"Successful", NULL, NULL);
	return NULL;
}

