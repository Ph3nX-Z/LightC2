from winim/lean import MAX_PATH, WCHAR, DWORD, WINBOOL, HANDLE
from winim/extra import PROCESSENTRY32, PROCESSENTRY32W, CreateToolhelp32Snapshot, Process32First, Process32Next
from strutils import parseInt, repeat, strip
from os import getCurrentProcessId
import winim


proc `$`(a: array[MAX_PATH, WCHAR]): string = $cast[WideCString](unsafeAddr a[0])

proc GetProcess*(): string =
    var 
        output: string
        processSeq: seq[PROCESSENTRY32W]
        processSingle: PROCESSENTRY32
    
    let 
        hProcessSnap  = CreateToolhelp32Snapshot(0x00000002, 0)

    processSingle.dwSize = sizeof(PROCESSENTRY32).DWORD
    
    if bool(Process32First(hProcessSnap, processSingle.addr)):
        while bool(Process32Next(hProcessSnap, processSingle.addr)):
            processSeq.add(processSingle)
    CloseHandle(hProcessSnap) 

    output = "PID\tNAME\t\t\t\tPPID\n"
    for processSingle in processSeq:
        var 
            procName : string = $processSingle.szExeFile
            procNamePadded : string

        try:
            procNamePadded = procName & " ".repeat(30-procname.len)
        except:
            procNamePadded = procName

        var ptu:LPVOID

        var getproresult = OpenProcess(PROCESS_ALL_ACCESS,TRUE,processSingle.th32ProcessID)
        #if getproresult == 0:
            #return "1"
        defer: CloseHandle(getproresult)

        var prochand:  HANDLE
        var resultbool = OpenProcessToken(getproresult, MAXIMUM_ALLOWED, addr prochand) 
        #if resultbool == FALSE:
            #return "1"




        output.add($processSingle.th32ProcessID & "\t" & procNamePadded & "\t" & $processSingle.th32ParentProcessID)

        # Add an indicator to the current process
        if parseInt($processSingle.th32ProcessID) == getCurrentProcessId():
            output.add("\t CURRENT PROCESS")

        output.add("\n")
    result = output.strip(trailing = true)

echo GetProcess()