

#ifndef PI_H
#define PI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <windows.h>
#include <psapi.h>
#include <winnt.h>
#include <Tlhelp32.h>

#include "loadlib.h"
#include "winexec.h"
#include "createthread.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef VOID (*pCreateRemoteThread64) (HANDLE hProcess, 
    LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPDWORD lpThreadId, LPHANDLE hThread);
  
#ifdef __cplusplus
}
#endif

typedef BOOL (*WINAPI pIsWow64Process)(HANDLE hProcess, PBOOL  Wow64Process);

#endif