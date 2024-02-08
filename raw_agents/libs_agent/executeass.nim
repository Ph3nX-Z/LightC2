import winim/clr
import os

proc dup(oldfd: FileHandle): FileHandle {.importc, header: "unistd.h".}
proc dup2(oldfd: FileHandle, newfd: FileHandle): cint {.importc,
    header: "unistd.h".}

func convertToByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

proc executeassembly(assembly_bytes: openarray[byte], args: openarray[string], tmpname: string) : string =
  let tmpFileName = getTempDir() & tmpname
  
  var stdout_fileno = stdout.getFileHandle()
  var stdout_dupfd = dup(stdout_fileno)
  
  var tmp_file: File = open(tmpFileName, fmWrite)
  var tmp_file_fd: FileHandle = tmp_file.getFileHandle()
  
  discard dup2(tmp_file_fd, stdout_fileno)
  
  var dotnetargs = toCLRVariant(args, VT_BSTR)
  var assembly = load(assembly_bytes)
  assembly.EntryPoint.Invoke(nil, toCLRVariant([dotnetargs]))

  tmp_file.flushFile()
  tmp_file.close()
  discard dup2(stdout_dupfd, stdout_fileno)

  result = readFile(tmpFileName)

proc read_file_content(filepath:string):string =
    var filecontent = readFile(filepath)
    return filecontent

when isMainModule:
    var outuot = read_file_content("./a.exe")
    var command_output = executeassembly(convertToByteSeq(outuot),[],"tempfile")
    echo $command_output
    #echo $outuot
