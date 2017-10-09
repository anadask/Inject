// RegInject.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
using namespace std;
wstring GetExeDirectory();
wstring GetParent(const std::wstring& FullPath);
int main()
{


	LONG ReturnValue = 0;
	HKEY hKey;
	WCHAR  RegPath[] = L"SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Windows";
	const wchar_t* DllName = L"Dll.dll";
	wstring InjectFileFullPath;
	InjectFileFullPath = GetExeDirectory() +
		L"\\" + DllName;
	RegEnableReflectionKey(HKEY_LOCAL_MACHINE);
	//打开键值  
	ReturnValue = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		RegPath,
		0,
		KEY_ALL_ACCESS,
		&hKey);

	if (ReturnValue != ERROR_SUCCESS)
	{
		return FALSE;
	}

	//查询键值  
	DWORD dwReadType;
	DWORD dwReadCount;
	WCHAR szReadBuff[1000] = { 0 };
	ReturnValue = RegQueryValueEx(hKey,
		L"AppInit_DLLs",
		NULL,
		&dwReadType,
		(BYTE*)&szReadBuff,
		&dwReadCount);

	if (ReturnValue != ERROR_SUCCESS)
	{
		return FALSE;
	}
	//是否dll名称已经在内容中  
	wstring strCmpBuff(szReadBuff);
	//strCmpBuff = szReadBuff;
	int a = strCmpBuff.find(InjectFileFullPath);
	if (strCmpBuff.find(InjectFileFullPath))
	{
		return FALSE;
	}

	//有字符串就加入空格  
	if (wcscmp(szReadBuff, L" ") != 0)
	{
		wcscat_s(szReadBuff, L" ");
	}

	wcscat_s(szReadBuff, InjectFileFullPath.c_str());

	//把dll路径设置到注册表中  
	ReturnValue = RegSetValueEx(hKey,
		L"AppInit_DLLs",
		0,
		REG_SZ,
		(CONST BYTE*)szReadBuff,
		(_tcslen(szReadBuff) + 1) * sizeof(TCHAR));
	DWORD v1 = 0;
	ReturnValue = RegSetValueEx(hKey,
		L"LoadAppInit_DLLs",
		0,
		REG_DWORD,
		(CONST BYTE*)&v1,
		sizeof(DWORD));
	return 0;
}

wstring GetExeDirectory()
{
	wchar_t ProcessFullPath[MAX_PATH] = { 0 };
	DWORD ProcessFullPathLength = ARRAYSIZE(ProcessFullPath);
	GetModuleFileName(NULL, ProcessFullPath, ProcessFullPathLength);

	return GetParent(ProcessFullPath);
}

wstring GetParent(const std::wstring& FullPath)
{
	if (FullPath.empty())
	{
		return FullPath;
	}
	auto v1 = FullPath.rfind(L"\\");
	if (v1 == FullPath.npos)
	{
		v1 = FullPath.rfind(L'/');
	}
	if (v1 != FullPath.npos)
	{
		return FullPath.substr(0, v1);
	}
	else
	{
		return FullPath;
	}
}