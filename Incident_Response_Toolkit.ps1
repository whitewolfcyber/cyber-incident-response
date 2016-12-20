<#
Thank you for using the Incident Response ToolKit!

For the best experience please adjust your default powershell windows to 200x35 for the Window Size

 Developed by Michael Horch
 Email - whitewolfcyber@outlook.com
 Blog - whitewolfcybersecurity.com
 Twitter - @WhiteWolf_Cyber

.SYNOPSIS
    This Toolkit will assist an Incident Responder in assessing basic information about a possibly compromised system.
    Common information like what ports are open, what processes and services are running, and what is hidding in the Registry is found
    through utilizing the menu.

.LINK
  www.github.com/whitewolfcyber/cyber-incident-response

#>
$PSExecLocation = "c:\SysinternalsSuite\psexec.exe"
$psexecCommand = "psexec.exe -s winrm.cmd quickconfig -q"
$SysinternalSuiteLocation = "C:\SysinternalsSuite"
$cred = Get-Credential
$IDRTmember = [Environment]::UserName
$powerForensicsLocation = "C:\Program Files\WindowsPowerShell\Modules\PowerForensics"

###################################################################################################################################################################
$menu=@"
 __  .__   __.   ______  __   _______   _______ .__   __. .___________.   .______       _______     _______..______     ______   .__   __.      _______. _______    
|  | |  \ |  |  /      ||  | |       \ |   ____||  \ |  | |           |   |   _  \     |   ____|   /       ||   _  \   /  __  \  |  \ |  |     /       ||   ____|   
|  | |   \|  | |  ,----'|  | |  .--.  ||  |__   |   \|  | `---|  |----`   |  |_)  |    |  |__     |   (----`|  |_)  | |  |  |  | |   \|  |    |   (----`|  |__      
|  | |  . `  | |  |     |  | |  |  |  ||   __|  |  . `  |     |  |        |      /     |   __|     \   \    |   ___/  |  |  |  | |  . `  |     \   \    |   __|     
|  | |  |\   | |  `----.|  | |  '--'  ||  |____ |  |\   |     |  |        |  |\  \----.|  |____.----)   |   |  |      |  `--'  | |  |\   | .----)   |   |  |____    
|__| |__| \__|  \______||__| |_______/ |_______||__| \__|     |__|        | _| `._____||_______|_______/    | _|       \______/  |__| \__| |_______/    |_______|   
                                                                                                                                                                    
                     .___________.  ______     ______    __       __  ___  __  .___________.                                                                        
                     |           | /  __  \   /  __  \  |  |     |  |/  / |  | |           |                                                                        
                     `---|  |----`|  |  |  | |  |  |  | |  |     |  '  /  |  | `---|  |----`                                                                        
                         |  |     |  |  |  | |  |  |  | |  |     |    <   |  |     |  |                                                                             
                         |  |     |  `--'  | |  `--'  | |  `----.|  .  \  |  |     |  |                                                                             
                         |__|      \______/   \______/  |_______||__|\__\ |__|     |__|                                                                             
                                                                                                                                                                    

1) Maunally Provide Remote PC Name (SYS12345)
2) Show Running Processes on a Remote PC
3) Show Running Services on a Remote PC
4) Enter a Remote Powershell Session
5) Ping
6) NSlookup
7) List Network Connections on a Remote PC
8) Get Registry Run and RunOnce Key Information
9) Manually Enable WinRM Service on Remote PC
10) Manually configure and stop WinRM service on Remote PC
Q) Quit
 
Select a task by number or Q to quit
"@
$option1SubMenu =@"

1) Print Process List to file
2) Display Process List
3) Back

Select a task by number
"@

$option2SubMenu =@"

1) Print Services List to file
2) Display Services List
3) Back

Select a task by number
"@

$option3SubMenu =@"

1) Create a Remote Powershell Session
2) Terminate Remote Powershell Session
3) Back

Select a task by number
"@

$option6SubMenu =@"

1) Display Network Connections
2) Print Network Connections to a file
3) Back

Select a task by number
"@

$option8SubMenu =@"

1) Get Registry Run Key Values and Print to a .txt file
2) Get Registry Run Key Values
3) Back
Select a task by number
"@

function Get-NetStat{
<#
.SYNOPSIS
    This function will get the output of netstat -n and parse the output
.DESCRIPTION
    This function will get the output of netstat -n and parse the output.
    
    Credit goes to PowerShell MVP Francois-Xavier Cat, who wrote the orignial function to parse the output of netstat.exe -n.
    
    I added the ability to query info from a remote system via Invoke-Command (requires that PowerShell remoting be enabled on
    the destination system), and then use the same functionality in the original script to parse the output. 
.PARAMETER ComputerName
    Name of remote system to query
.LINK
	http://www.lazywinadmin.com/2014/08/powershell-parse-this-netstatexe.html
.LINK
  www.github.com/vN3rd
	
#>
	
	[cmdletbinding()]
	param (
		[parameter(Mandatory = $false,
				   Position = 0,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[ValidateScript({ Test-Connection -ComputerName $_ -Count 2 -Quiet })]   
		[string]$ComputerName = 'localhost'
	)
	
	BEGIN
	{
		if ($ComputerName -eq 'localhost')
		{
			$NetStat = netstat.exe -naob
		} else
		{
			$NetStat = Invoke-Command -ComputerName $ComputerName -ScriptBlock { netstat.exe -naob }
		}# end if/else
	}# end BEGIN
	
	PROCESS
	{

		# Keep only the line with the data (we remove the first lines)
		$NetStat = $NetStat[4..$NetStat.count]
		
		# Each line need to be splitted and get rid of unnecessary spaces
		foreach ($line in $NetStat)
		{
			# Get rid of the first whitespaces, at the beginning of the line
			$line = $line -replace '^\s+', ''
			
			# Split each property on whitespaces block
			$line = $line -split '\s+'
			
			# Define the properties
			$properties = @{
				Protocol = $line[0]
				LocalAddressIP = ($line[1] -split ":")[0]
				LocalAddressPort = ($line[1] -split ":")[1]
				ForeignAddressIP = ($line[2] -split ":")[0]
				ForeignAddressPort = ($line[2] -split ":")[1]
				State = $line[3]
			}
			
			# Output the current line
			New-Object -TypeName PSObject -Property $properties
			
		}# end foreach
	}# end PROCESS
}# end function Get-NetStat

Function Invoke-Menu {
[cmdletbinding()]
Param(
[Parameter(Position=0,Mandatory=$True,HelpMessage="Enter your menu text")]
[ValidateNotNullOrEmpty()]
[string]$Menu,
[Parameter(Position=1)]
[ValidateNotNullOrEmpty()]
[string]$Title = "My Menu",
[Alias("cls")]
[switch]$ClearScreen
)

#clear the screen if requested
if ($ClearScreen) { 
 Clear-Host 
}

#build the menu prompt
$menuPrompt = $title
#add a return
$menuprompt+="`n"
#add an underline
$menuprompt+="-"*$title.Length
#add another return
$menuprompt+="`n"
#add the menu
$menuPrompt+=$menu

Read-Host -Prompt $menuprompt

} #end function
$systemName = Read-Host -Prompt "Please Provide the remote system name"
Write-Host "Checking if you have SysinternalsSuite at C:\" -ForegroundColor Yellow
         sleep -Seconds 2
            if (Test-Path $SysinternalSuiteLocation)
                {
                Write-Host "SysinternalSuite Found!" -ForegroundColor Green
                }
                else
                    {
                    Write-Host "Sysinternals cannot be found...downloading it for you to C:\" -ForegroundColor Red
                    Copy-Item '\\fb959\c$\inetpub\ftproot\FTP\IDRT_Tools\SysinternalsSuite' C:\ -Recurse -ErrorAction SilentlyContinue
                    sleep -Seconds 5
                                if (Test-Path $SysinternalSuiteLocation)
                                    {
                                    Write-Host "SysinternalsSuite has been downloaded to your C:\ drive" -ForegroundColor Green
                                    }
                                }
                            
    
                  $WinRM = Get-WMIObject Win32_Service -Filter "name='WinRM'" -computer $systemName -Credential $cred | Select State
                         if ($WinRM = "Stopped")
                            {
                                Write-Host "Enabling the WinRM Service on $systemName" -ForegroundColor Yellow
                                Start-Process -WindowStyle Hidden -FilePath "C:\SysinternalsSuite\PsExec.exe" -Credential $cred -ArgumentList "\\$systemName -s net start winrm"; 
                                Start-Process -WindowStyle Hidden -FilePath "C:\SysinternalsSuite\PsExec.exe" -Credential $cred -ArgumentList "\\$systemName -s winrm.cmd quickconfig -q"
                                sleep -Seconds 3
                                $WinRM = Get-WMIObject Win32_Service -Filter "name='WinRM'" -computer $systemName -Credential $cred | Select State
                                    if ($WinRM = "Running")
                                    {
                                    Write-Host "WinRM service started...you can now proceed with your other tasks!" -ForegroundColor Green
                                    sleep -Seconds 5
                                    }
                                    }
                                    else
                                    {
                                    Write-Warning "Something went wrong!"; Read-Host "Press Enter to quit"
                                    }
                            else
                            {
                            Write-Host "WinRM service started...you can now proceed with your other tasks!" -ForegroundColor Green
                            }
                                    
Do {
    #use a Switch construct to take action depending on what menu choice
    #is selected.
    Switch (Invoke-Menu -menu $menu -title "                    " -clear) 
    {

#Get System Name
   "1" {$systemName = Read-Host -Prompt "Please Provide the remote system name"}

#Running Processes
   "2" {
            $a = @{Expression={$_.Name};Label="Process Name";width=25}, `
                 @{Expression={$_.ID};Label="PID";width=15}, `
                 @{Expression={$_.Path};Label="Path";width=80}
            $option1SubMenuOptions = Read-Host $option1SubMenu
                Switch ($option1SubMenuOptions) 
                {
                    "1" {
                        Write-Host "Getting Process Information" -ForegroundColor Yellow
                        sleep -Seconds 2
                        Invoke-Command {Get-Process} -ComputerName $systemName -Credential $cred | Format-Table $a | Out-File "C:\Users\$IDRTmember\Desktop\$systemName.Processes.txt"
                        Write-Host "Process Information Successfully saved to your Desktop as $systemName.Processes.txt" -ForegroundColor Green
                        sleep -Seconds 5
                    }

                    "2" {Invoke-Command {Get-Process} -ComputerName $systemName -Credential $cred | Format-Table $a
                        Read-Host -Prompt "Press Enter When Done"

                    }

                    "3" {
                       

                    } #end switch
         Default {Write-Warning "Invalid Choice. Try again."}
                 } 

         }
 
#Running Services
   "3" {$option2SubMenuOptions = Read-Host $option2SubMenu
                Switch ($option2SubMenuOptions) 
                {
                    "1" {
                        Write-Host "Getting Services Information" -ForegroundColor Yellow
                        sleep -Seconds 2
                        Invoke-Command -ComputerName $systemName -Credential $cred {tasklist} | Out-File "C:\Users\$IDRTmember\Desktop\$systemName.Services.txt"
                        Write-Host "Service Information Successfully saved to your Desktop as $systemName.Services.txt" -ForegroundColor Green
                        sleep -Seconds 5
                        }
                    "2" {
                    Invoke-Command -ComputerName $systemName -Credential $cred {tasklist}
                        Read-Host -Prompt "Press Enter When Done"

                    }

                    "3" {
                       

                    } #end switch
         Default {Write-Warning "Invalid Choice. Try again."}
                 } 
        }

#Enter-PSSession
   "4" {$option3SubMenuOptions = Read-Host $option3SubMenu
                Switch ($option3SubMenuOptions) 
                {
                    "1" {
                        Write-Host "Attempting to connect to $systemName using Remote Powershell Session" -ForegroundColor Yellow
                       
                        Enter-PSSession -ComputerName $systemName -Credential $cred
                        Write-Host "Remote Session Active - to enter session you have to exit this script" -ForegroundColor Green
                        sleep -Seconds 3   
                        
                        }
                    "2" {
                        Write-Host "Attempting to terminate Remote Powershell Session on $systemName" -ForegroundColor Yellow
                        Exit-PSSession -ComputerName $systemName -Credential $cred
                        Write-Host "Remote Session Terminated" -ForegroundColor Red
                        sleep -Seconds 3
                        }
                    "3" {
                        }#end switch
                        Default {Write-Warning "Invalid Choice. Try again."}
                 } 
        }

#Ping System
   "5" {
           Write-Host "Pinging $systemName" -ForegroundColor Yellow
           if( Test-Connection $systemName -Quiet){write-Host "Remote System is Up!" -ForegroundColor Green}
           else{write-Host "Remote System is DOWN :(" -ForegroundColor Red}
           Read-Host -Prompt "Press Enter When Done"
        } 

#NSLookup
   "6" {
           Write-Host "Performing NSlookup for $systemName" -ForegroundColor Yellow
           nslookup $systemName
           Read-Host -Prompt "Press Enter When Done"

        } 

#Network Connections
   "7" {
           Write-Host "Pinging $systemName" -ForegroundColor Yellow
           if( Test-Connection $systemName -Quiet)
           {
           write-Host "Remote System is Up!" -ForegroundColor Green
           }
           else
           {
           write-Host "Remote System is DOWN :(" -ForegroundColor Red
           }
           sleep -Seconds 2
           
           $option6SubMenuOptions = Read-Host $option6SubMenu
                Switch ($option6SubMenuOptions) 
                {                
                    "1" {
                    
                        Write-Host "Getting $systemName network connection information" -ForegroundColor Yellow
                        Invoke-Command -Credential $cred -ComputerName $systemName -ScriptBlock ${function:Get-NetStat} | Format-Table -AutoSize
                        Read-Host -Prompt "Press Enter When Done"
                        
                        }
                        
                        
                    "2" {
                    
                        Write-Host Write-Host "Getting $systemName network connection information and saving to C:\Users\$IDRTmember\Desktop\$systemName.NetworkConnections.txt" -ForegroundColor Yellow
                        Invoke-Command -Credential $cred -ComputerName $systemName -ScriptBlock ${function:Get-NetStat} | Format-Table -AutoSize | Out-File "C:\Users\$IDRTmember\Desktop\$systemName.NetworkConnections.txt"
                        sleep -Seconds 2
                        Write-Host "Completed Successfully" -ForegroundColor Green
                        Read-Host "Press Enter When Done"
                        }
                        }
                        
        }
        
#Check Registry Key
   "8" {
    $remoteUser = Read-Host -Prompt "Please provide the User Name of the individual that uses the Remote PC"
    $powerShellGetLocation = "C:\Program Files\WindowsPowerShell\Modules\PowerShellGet"
    $powerForensicsLocation = "C:\Program Files\WindowsPowerShell\Modules\PowerForensics"
    Write-Host "Checking if you have PowerForensics Module Installed" -ForegroundColor Yellow
         sleep -Seconds 2
            if (Test-Path "c:\Program Files\WindowsPowerShell\Modules\PowerForensics")
                {
                Write-Host "PowerForensics Module is installed" -ForegroundColor Green
                }
            else
                {
                Write-Host "PowerForensics Module Required - downloading now" -ForegroundColor Red
                Copy-Item '\\fb959\c$\inetpub\ftproot\FTP\IDRT_Tools\PowerForensics' -Destination  '%ProgramFiles%\WindowsPowerShell\Modules'
                sleep -Seconds 5
                }
                              
            Write-Host "Checking Host Prerequisites..." -ForegroundColor Yellow
            if (Invoke-Command -Credential $cred -ComputerName $systemName -ScriptBlock {Test-Path -Credential $cred "c:\Program Files\WindowsPowerShell\Modules\PowerForensics"})
                {
              Write-Host "Host Prerequisites Check Passed" -ForegroundColor Green
                              }
            else
                {
                Write-Host "Host Prerequisites Check Failed...correcting the issue" -ForegroundColor Red
                Invoke-Command -Credential $cred -ComputerName $systemName -ScriptBlock {Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force}
                Invoke-Command -Credential $cred -ComputerName $systemName -ScriptBlock {Install-Module -Name PowerForensics -Force}
                    if (Invoke-Command -Credential $cred -ComputerName $systemName -ScriptBlock {Test-Path -Credential $cred "c:\Program Files\WindowsPowerShell\Modules\PowerForensics"})
                        {
                        Write-Host "Host Prerequisites Check Passed" -ForegroundColor Green
                        }
                
                        else
                        {
                        Write-Host "Host Prerequisites Check Failed..." -ForegroundColor Red
                        } 
                }

            sleep -Seconds 1
                                
           $option8SubMenuOptions = Read-Host $option8SubMenu
                Switch ($option8SubMenuOptions) 
                {
                    "1" {
                        Write-Host "Getting Registry Run Key Information" -ForegroundColor Yellow
                        Import-Module -Name PowerForensics
                        Invoke-Command -Credential $cred -ComputerName $systemName -ScriptBlock {$remoteUser = $args[0]; Get-ForensicRunKey -HivePath "C:\Windows\System32\config\SOFTWARE"; 
                        Get-ForensicRunKey -HivePath "C:\users\$remoteUser\NTUSER.DAT"} -ArgumentList $remoteUser | Out-File "C:\Users\$IDRTmember\Desktop\$systemName.RegistryValues.txt"
                        Write-Host "Registry Information Successfully saved to your Desktop as $systemName.RegistryValues.txt" -ForegroundColor Green
                        sleep -Seconds 5
                        }

                    "2" {
                        Write-Host "Getting Registry Run Key Information" -ForegroundColor Yellow
                        Import-Module -Name PowerForensics
                        Invoke-Command -Credential $cred -ComputerName $systemName -ScriptBlock {$remoteUser = $args[0]; Get-ForensicRunKey -HivePath "C:\Windows\System32\config\SOFTWARE"; 
                        Get-ForensicRunKey -HivePath "C:\users\$remoteUser\NTUSER.DAT" | Format-Table -AutoSize } -ArgumentList $remoteUser
                        Read-Host -Prompt "Press Enter When Done"

                    }

                    "3" {
                       

                    } #end switch
         Default {Write-Warning "Invalid Choice. Try again."}
                 }  
          }

#Manually Enable WinRM
   "9" {
         Write-Host "Enabling the WinRM Service on $systemName" -ForegroundColor Yellow
                  $WinRM = Get-WMIObject Win32_Service -Filter "name='WinRM'" -computer $systemName -Credential $cred | Select State
                         if ($WinRM = "Stopped")
                            {
                            Start-Process -WindowStyle Hidden -FilePath "C:\SysinternalsSuite\PsExec.exe" -Credential $cred -ArgumentList "\\$systemName -s net start winrm"; 
                            Start-Process -WindowStyle Hidden -FilePath "C:\SysinternalsSuite\PsExec.exe" -Credential $cred -ArgumentList "\\$systemName -s winrm.cmd quickconfig -q"
                            sleep -Seconds 3
                            $WinRM = Get-WMIObject Win32_Service -Filter "name='WinRM'" -computer $systemName -Credential $cred | Select State
                            if ($WinRM = "Running"){Write-Host "WinRM service started...you can now proceed with your other tasks!" -ForegroundColor Green}
                            sleep -Seconds 5
                            else
                            {
                            Write-Warning "Something went wrong!"; Read-Host "Press Enter to quit"
                            }
                                }
                                    sleep -Seconds 2
         
                                    
         
                               
           
         }
 
 #Manually ReConfigure WinRM to Default Settings
  "10" {
            Write-Host "Returning Remote PC to Default WinRM configuration settings" -ForegroundColor Yellow
            Start-Process -WindowStyle Hidden -FilePath "C:\SysinternalsSuite\PsService.exe" -Credential $cred -ArgumentList "\\$systemName setconfig winrm demand"
            sleep -Seconds 2
            Start-Process -WindowStyle Hidden -FilePath "C:\SysinternalsSuite\PsService.exe" -Credential $cred -ArgumentList "\\$systemName stop winrm"
            sleep -Seconds 5
            $WinRM = Get-WMIObject Win32_Service -Filter "name='WinRM'" -computer $systemName -Credential $cred | Select State
                if ($WinRM = "Stopped")
                {Write-Host "WinRM service successfully stopped" -ForegroundColor Green}
                else
                {
                write-Host "An error prevented the WinRM service from stopping" -ForegroundColor Red
                }
            
            sleep -Seconds 4
        } 

   "Q" {Write-Host "Verifying Remote PC WinRM service has been reset to default settings" -ForegroundColor Yellow
        
         $WinRM = Get-WMIObject Win32_Service -Filter "name='WinRM'" -computer $systemName -Credential $cred | Select State
                  if ($WinRM = "Running")
                  {
                    Start-Process -WindowStyle Hidden -FilePath "C:\SysinternalsSuite\PsService.exe" -Credential $cred -ArgumentList "\\$systemName setconfig winrm demand"
                    sleep -Seconds 2
                    Start-Process -WindowStyle Hidden -FilePath "C:\SysinternalsSuite\PsService.exe" -Credential $cred -ArgumentList "\\$systemName stop winrm"
                    sleep -Seconds 5
                  }
         $WinRM = Get-WMIObject Win32_Service -Filter "name='WinRM'" -computer $systemName -Credential $cred | Select State
                if ($WinRM = "Stopped")
                {
                Write-Host "WinRM service successfully stopped" -ForegroundColor Green
                }
                else
                {
                write-Host "An error prevented the WinRM service from stopping - manually stop the service through the service.msc GUI" -ForegroundColor Red
                sleep -Seconds 5
                }
        Write-Host "Goodbye" -ForegroundColor Cyan
        sleep -Seconds 5
        Return
         }

     Default {Write-Warning "Invalid Choice. Try again."
              sleep -milliseconds 750}
    } #switch
    
    
} While ($True)