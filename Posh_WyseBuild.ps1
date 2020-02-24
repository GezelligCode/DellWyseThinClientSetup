alias npp='notepad++ -multiInst -nosession'
####VARIABLES####

$Admin = Read-Host -Prompt 'Enter Your Admin Username'
$Domain = "Corp"
$CorpDomainAdmin = "${Domain}\${Admin}"
$Hostname = hostname
$NewPCName = Read-Host -Prompt 'Enter the New PC Name'
$Tmp = "C:\Temp"
$NetXCleanFile = "C:\Windows\System32\NetXClean.ini"
$Tools = "\\Corpdocs\NetShare\HealthIT\Tools"
$Apps = "\\Corpdocs\NetShare\HealthIT\Apps"
$Sym = "\\Corpsep\Distribution\SEP_14_2_RU1_MP1_x64"
$Dameware = "${Tools}\Dameware MiniRemote MSI Installer"
$DamewareExec = "${Tmp}\Dameware MiniRemote MSI Installer\Corp_DamewareMiniRemoteInstall.MSI"
$DamewareArgs = "/quiet"
$PCMgmt = "${Tools}\PowerShellScripting\WinEmbedded\BatFiles\PCMgmtAdminSetup.cmd"
$Symantec = "${Sym}\Silent Setup for Script.exe"
$SymantecExec = "${Tmp}\Silent Setup for Script.exe"
$Adobe = "${Apps}\Adobe\Reader DC"
$AdobeExec = "${Tmp}\Reader DC\AcroRdrDC1700920044_en_US.exe"
$AdobeExecArgs = "/sAll"
$ExamRollOut = “\\Corpdocs\NetShare\HealthIT\Vendors\MidMark\Exam Unit RollOut”
$MidmarkUSBInstaller = “${Tmp}\Exam Unit RollOut\Temp\Midmark IQvitalsUSBInstaller\IQvitalsUSBInstaller.exe”
$MidMarkIQPathSetup = “${Tmp}\Exam Unit RollOut\Temp\MidMark IQpath\setup.exe”
$MidMarkIQRegedit = “${Tmp}\Exam Unit RollOut\Temp\MidMark IQpath\MidmarkRdp.reg”
$MidarmIQVitalsPatch = “${Tmp}\Exam Unit RollOut\Temp\IQvitalsPatch.exe”
$MidMarkUSBIQDevices = "C:\Brentwood\Programs\IQdevicesUSBDrivers\InstallMDGUSBOnlyDrivers.exe"
$MidmarkUSBIQVitals = "C:\Brentwood\Programs\IQvitalsUsbDrivers\InstallIQvitalsusbDrivers.exe" 
$NextGenShortcut = "C:\Tools\NextGen.lnk"
$ScreenSaver = "\\docs\Operations\ExamRoomScreenSavers\ScreenSavers"


####EXECUTION####

#Execution policies
set-executionpolicy -ExecutionPolicy Unrestricted -Force

#Run the following block under the Admin user account

    #Check if starting on initial Admin acct. If so, initiate NetXClean setup and Admin user setup.
    If ($env:USERNAME -eq "Admin") {

        $UwfmgrStatus = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WNT\UWFSvc\' -Name 'WF_Status'

        If ($UwfmgrStatus -eq 0) {

        Write-Host 'Disabling write filter'

        uwfmgr.exe filter disable

        Write-Host 'Restarting PC to apply write-filter changes'

        Start-Sleep -Seconds 10

        Restart-Computer
        } ElseIf ($UwfmgrStatus = 1) {

            Write-Host 'Write-filter disabled. Building NetXClean file'

            #Add User Profiles to NetXClean Exception List
            (Get-Content $NetXCleanFile) | 
                ForEach-Object {
                    $_
                    if ($_ -match "P2=User")
                    {

                        "P3=${NewPCName}.User"
                        "P4=Administrator"
                        "P5=${Admin}"

                    }
                } | Set-Content $NetXCleanFile

            #Restart NetXClean Service
            restart-service "netxclean"

            Write-Host 'NetXClean setup complete. Setting up admin accounts'

            #Run batch script for enabling administrator and disabling admin and setting applicable passwords for each. 
            #Apparently requires two passes to take care of both the admin and administrator, thus the two instances below. 
            Write-Host 'Setting up Admin User Accounts'
            start-process $PCMgmt -Wait
            start-process $PCMgmt -Wait


            Write-Host 'Admin account setup complete. Logging off in 10 seconds. Sign back in as Administrator'
            Start-Sleep -Seconds 10


            Logoff;Exit        
        }
    }

#Run the following block under the Administrator user account

    #Add Terminal to Domain
    If ($env:USERDOMAIN -ne $Domain) {


        Write-Host 'Joining to Corp Domain'

        $DomainCred = Get-Credential -Message 'Enter your domain-joining credentials'

        Add-Computer -DomainName "${Domain}.org" -Credential $DomainCred -Force

        Write-Host 'Rebooting in 5 seconds'

        Start-Sleep -Seconds 5

        Restart-Computer

        } 

#The remaining script can be run as the domain admin user

#Rename Computer and Configure Auto-logon
If ($HostName -ne $NewPCName) {

        #Rename 
        Rename-Computer -ComputerName $Hostname -NewName $NewPCName -DomainCredential $CorpDomainAdmin -Force

        #Auto-logon
        set-itemproperty "HKLM:\Software\Microsoft\windows NT\CurrentVersion\Winlogon" -name AutoAdminLogon -value "1"
        set-itemproperty "HKLM:\Software\Microsoft\windows NT\CurrentVersion\Winlogon" -name DefaultDomainName -value "Corp.org"
        $User = ".User"
        $DefaultUserName = $NewPCName+$User
        #The line below assumes the "A123B.User" naming scheme.
        $roomNumber = $NewPCName.substring(1,3)
        $passRoot = "#x!t#xam"
        $passWord = $passRoot+$roomNumber
        set-itemproperty "HKLM:\Software\Microsoft\windows NT\CurrentVersion\Winlogon" -name DefaultUserName -value $DefaultUserName
        new-ItemProperty "HKLM:\Software\Microsoft\windows NT\CurrentVersion\Winlogon" -name DefaultPassword -value $passWord

        Restart-Computer

        }


#Create C:\Temp folder for later use
New-Item -Path $Tmp -ItemType Directory
Write-Host 'C:\Temp created'

#Turn off hibernation
Powercfg.exe /hibernate off
Write-Host 'Hibernation turned off'

#Disable Windows firewall
Set-NetFirewallProfile –Profile Domain,Public,Private –Enabled False
Write-Host 'Firewall disabled'

#Set HST
TZUtil /s "Hawaiian Standard Time"
Write-Host 'Hawaii Time enabled'

#Set environment variables for Temp and Tmp folders
[Environment]::SetEnvironmentVariable("Temp", "C:\Windows\Temp", "Machine")
[Environment]::SetEnvironmentVariable("Tmp", "C:\Windows\Tmp", "Machine")
[Environment]::SetEnvironmentVariable("Temp", "C:\Windows\Temp", "User")
[Environment]::SetEnvironmentVariable("Tmp", "C:\Windows\Tmp", "User")
Write-Host 'User and system environment variables set'

#Set proxy server, turn off auto-detect, and turn on proxy bypass for local addresses
new-itemproperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -name "AutoDetect" -value "0" -PropertyType DWORD -force
netsh winhttp set proxy 192.168.0.2:3128
set-itemproperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -name ProxyEnable -value "1"
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -name ProxyServer -value "http://192.168.0.2:3128"
#Line below is apparently extraneous, but need further testing to be sure.
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" -Name ProxyByPass -Value "0" -PropertyType DWORD -force
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$data = (Get-ItemProperty -Path $key -Name DefaultConnectionSettings).DefaultConnectionSettings
$data[4] = 1
$data[8] = 3
Write-Host 'Proxy server settings established'

#Remove All Shortcuts & Erroneous Links to Unneeded Programs
Remove-Item C:\Users\*\Desktop\*lnk -force
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\MiracastView.lnk" -force
Write-Host 'Desktop wiped clean'

Copy-Item $Dameware -container -recurse -destination $Tmp
Start-Process $DamewareExec $DamewareArgs -Wait
Write-Host 'Dameware installed'

#Install Adobe DC
Copy-Item $Adobe -Container -Recurse -Destination $Tmp
Start-Process $AdobeExec $AdobeExecArgs -Wait
Write-Host 'Adobe DC installed'

#Install Symantec client
Copy-Item $Symantec -Container -recurse -destination $Tmp
#Start-Sleep -Seconds 200
Start-Process $SymantecExec -Wait
Write-Host 'Symantec installed'

#Disable Indexing on C:\
Disable-WindowsOptionalFeature -Online -FeatureName "SearchEngine-Client-Package" -NoRestart
Write-Host 'Indexing disabled'

#Uninstall Programs
$OffPCPlz = Get-WmiObject -class win32_product -Filter "name like '%Bluetooth%'"
$OffPCPlz.Uninstall()
Start-Sleep -Seconds 60
Write-Host 'Intel Bluetooth uninstalled'

$OffPCPlz = Get-WmiObject -class win32_product -Filter "name like '%Intel%'"
$OffPCPlz.Uninstall()
Start-Sleep -Seconds 60
Write-Host 'Intel Wireless ProSet uninstalled'

$OffPCPlz = Get-WmiObject -class win32_product -Filter "name like '%Citrix%'"
$OffPCPlz.Uninstall()
Start-Sleep -Seconds 60
Write-Host 'Citrix Apps uninstalled'

$OffPCPlz = Get-WmiObject -class win32_product -Filter "name like '%Ericom%'"
$OffPCPlz.Uninstall()
Start-Sleep -Seconds 60
Write-Host 'Ericom uninstalled'

#Unregister from TightVNC (which also uninstalls the service) & Remove Applicable Folders
& 'C:\Program Files\TightVNC\TVNServer' -Remove
Remove-Item -Path "C:\Program Files\TightVNC" -Recurse
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TightVNC" -Recurse
Remove-item -path "HKLM:\SOFTWARE\TightVNC" -Recurse
Write-Host 'TightVNC uninstalled'

#Copy MidMark Items to Temp and Begin Installation
Copy-item $ExamRollOut -container -recurse -destination $Tmp
Start-process $MidmarkUSBInstaller -Wait
Start-process $MidMarkIQPathSetup -Wait
Start-process $MidMarkIQRegedit -Wait
Start-process $MidarmIQVitalsPatch -Wait
Start-Process $MidMarkUSBIQDevices -Wait
Start-Process $MidmarkUSBIQVitals -Wait

#Move C:\Temp\Exam Unit Rollout\Tools folder to C:\, so that tools will be found at C:\Tools.

copy-item -Path "C:\Temp\Exam Unit RollOut\Tools" -Recurse -Destination "c:\"

#Create shortcuts to the RDP folder to specified folders

copy-item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Acrobat Reader DC.lnk" -Destination "C:\Users\Public\Desktop\"
copy-item -Path $NextGenShortcut -Destination "C:\Users\Public\Desktop\"
copy-item -Path $NextGenShortcut -Destination "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\"
copy-item -Path $NextGenShortcut -Destination "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

#Create shortcut to IE on desktop:
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("C:\Users\Public\Desktop\Internet Explorer.lnk")
$shortcut.TargetPath = "C:\Program Files\Internet Explorer\iexplore.exe"
$shortcut.Save()

#Map netshare folder for screen saver images to P:
New-PSDrive "P" -Root $ScreenSaver -Persist -PSProvider FileSystem