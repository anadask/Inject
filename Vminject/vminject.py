# -*- coding:utf-8 -*-
from ctypes import *
import ctypes
import os
import psutil
import re
import sys


def InjectDll(pid,dll_Path):
    PAGE_RW_PRIV = 0x04
    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
    VIRTUAL_MEM = (0x1000 | 0x2000)

    kernel32 = windll.kernel32
    print ("[+] Starting DLL Injector")
    dllLength = len(dll_path)
    print("[+] Getting Process Handle From ProcessId %d" ,pid)
    #打开进程的进程句柄
    ProcessHandle = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)
    if ProcessHandle == None:
        print("Unable to Get Process Handle")
        sys.exit(0)

    print("In TargetProcess Alloc Buffer Space")
    #在对方虚拟内存地址中申请内存 ，存放DLL的地址
    DLL_PATH_ADDR = kernel32.VirtualAllocEX(ProcessHandle,
                                            0,
                                            dllLength,
                                            VIRTUAL_MEM,
                                            PAGE_RW_PRIV)
    bool_Write = c_int(0)
    print("Writing Dll Path to Target Process Space")
    #将动态库的地址写入目标进程中
    kernel32.WriteProcessMemory(ProcessHandle,
                              DLL_PATH_ADDR,
                              dll_Path,
                              dllLength,
                              byref(bool_Write))

    #得kernel32.dll模块的地址
    print("\t[+] Resolving Call Spacific function & librarise")
    kernel32DllHandle = kernel32.GetModuleHandleA("kernel32.dll")

    #得LoadLibrary函数地址
    LoadlibraryAddr = kernel32.GetProcAddress(kernel32DllHandle)

    thread_id = c_ulong(0)
    ThreadHandle = kernel32.CreateRemoteThread(ProcessHandle,
                                              None,
                                              0,
                                              LoadlibraryAddr,
                                              DLL_PATH_ADDR,
                                              0,byref(thread_id))

    if not ThreadHandle:
        print("Injection Failed exiting ")
        sys.exit(0)
    else:
        print("Remote Thread Id %d" ,thread_id)






if __name__ == "__main__":

    pid = input("输入进程ID")
    target = []
    i = 0
    # 判断计算机版本
    if str(ctypes.sizeof(ctypes.c_voidp)) == '4':
        print("Runing on a X86 machine seleteing DLL")
        dll_path = os.path.abspath("vminjector32.dll")
    else:
        print("Running on a x64 machine selecting DLL")
        dll_path = os.path.abspath("vminjector64.dll")

    print('Configured DLL path to %s \n' % dll_path)
    InjectDll(pid,dll_path)


