#Security Concerns
#If you use a scheduled task (or some other means) to run this script as "NT Authority\Local System" (or another privileged account) and point it to a network share containing this script. Ensure that the share is writable only by highly trusted accounts (sysvol/netlogon are good candidates). This is because unless you sign this script there is no validation, so if someone can replace this script with an evil version.. they can do what they wish.
#There are validations ensuring sysmon.exe and sysmon64.exe are the legitimate binaries before we execute them. So you can place these and the configuration somewhere less secure. However, even then it is possible to cause a DOS by overwriting a legitimate sysmon configuration with a poor configuration.  

# Updated December 16 2020
# Added a digital signature & other checks before executing sysmon.exe.
# Made improvements to support most recent versions of sysmon
# Added more context to the log file 

# Ensure to change the $ADDomainName to your domain name on line 3;
# Ensure to complete the path to the directory where you will keep Sysmon.exe including the preceding "\"; Sysmon64.exe; and the config sysmonconfig.xml on line 7;
# Only change these variables and no other variables

$ADDomainName = "example.nonexdom"
$SysVolSysmonPath = "\\$ADDomainName\sysvol\$ADDomainName\sysmon" #Place both sysmon64.exe and sysmon.exe in this directory
$LocalSysmonPath = "$Env:SystemRoot\Temp\" #default is C:\windows\temp, you should probably leave this as is
$SysVolSysmonConfig = "$SysVolSysmonPath\config.xml" #change config.xml to the name of your sysmon config file
#The path to sysmon.exe is dynamically generated based off if a x64 or x86 version of windows is in use. 
$LocalSysmonConfig = "$LocalSysmonPath\sysmonconfig.xml"
$LogFileForScript = "$LocalSysmonPath\sysmon-install-log.txt" #this is the log file, it contains the status of the script

# Set time that script started
$ScriptRunTime = Get-Date


#If log file does not already exist create it, so the rest of the script can just use add-content
if (-Not (Test-Path $LogFileForScript))
{
    Set-Content $LogFileForScript "" -NoNewline
}

Add-Content $LogFileForScript ""
Add-Content $LogFileForScript "$ScriptRunTime ---- Script is running"

Function main{

# Determines if OS is 64 or 32-bit
if([System.IntPtr]::Size -eq 4) {$Sysmon = "Sysmon.exe"; $SysmonService = "Sysmon"} else {$Sysmon = "Sysmon64.exe"; $SysmonService = "Sysmon64"}
$SysVolSysmonPE = "$SysVolSysmonPath\$Sysmon"

# Set local variables for when we copy config and PE to device
$LocalSysmonPE = "$LocalSysmonPath\$Sysmon"
if((Test-Path "$SysVolSysmonPE") -and (Test-Path "$SysVolSysmonConfig"))
{

    $SysmonVersionAvailable=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($SysVolSysmonPE).FileVersion

    # Finds sysmon.exe at C:\windows\sysmon.exe or sysmon64.exe
    $InstalledSysmon = Test-Path $Env:windir\$Sysmon
    # When you remove sysmon, it doesn't remove the EXE.. so do another check 
    $InstalledSysmonAsAService = get-service -Name "sysmon64" -ErrorAction SilentlyContinue
    # We want to log that for some reason sysmon.exe exists on the host but it is not a service :0
    # Usually this means that at one point it was installed
    if (-Not $InstalledSysmonAsAService)
    {
        Add-Content $LogFileForScript "$ScriptRunTime ---- Service was uninstalled at some point! May want to figure out why..."
    }

    if (($InstalledSysmon -eq $true) -and ($InstalledSysmonAsAService)) {

        # Get current sysmon version
        $SysmonVersion=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($SysVolSysmonPE).FileVersion

        # Convert strings to integers for comparison
        [double]$intSysmonAvailable = [convert]::ToDouble($SysmonVersionAvailable)
        [double]$intSysmonVersion = [convert]::ToDouble($SysmonVersion)

        # If sysvol version is greater than current version update
        if($intSysmonAvailable -gt $intSysmonVersion)
        {
            # Copy sysmon locally, for install performance and incase network drops during install
            cmd /c "copy /V $SysVolSysmonPE $LocalSysmonPE"
            cmd /c "copy /V $SysVolSysmonConfig $LocalSysmonConfig"
            # Make sure copies where successful
            if((Test-Path $LocalSysmonPE) -and (Test-Path $LocalSysmonConfig) -and (get-authenticodesignature $LocalSysmonPE) -and ((get-item "\\example.nonexdom\sysvol\example.nonexdom\sysmon\sysmon64.exe").versioninfo.ProductName -eq "Sysinternals Sysmon"))
            {
                
                cmd /c "$SysmonService -u"
                cmd /c "$SysmonService -accepteula -i $LocalSysmonConfig"
                Add-Content $LogFileForScript "$ScriptRunTime ---- Updated PE."
            }

            else {
                Add-Content $LogFileForScript "$ScriptRunTime ---- Failed to copy sysmon items."
                exit
            }
        }

        else {
            Add-Content $LogFileForScript "$ScriptRunTime ---- Current Sysmon is Up To Date"
        }

        # If sysmon drv last write time is later than last write time of sysvol config file, update the config.

        # Obtain sysvol sysmonconfig.xml last write time
        $sysvolconfiglastwrite = (get-item $SysVolSysmonConfig).LastWriteTime

        # Obtain current configuration last write time, this is available in the registry
        $key = get-item "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
        $localconfiglastwrite = ($key | Get-RegistryKeyTimestamp).LastWriteTime

        # Finally, compare both write times. If the lastwrite for the sysvol config is greater than the lastwrite for the registry.. update config
        if($sysvolconfiglastwrite -gt $localconfiglastwrite)
        {
            # Copy config locally, for install performance and incase network drops during install
            cmd /c "copy /V $SysVolSysmonConfig $LocalSysmonConfig"
            # Make sure network copy was successful
            if(Test-Path $LocalSysmonConfig)
            {
                cmd /c "$LocalSysmonPE -c $LocalSysmonConfig"
                Add-Content $LogFileForScript "$ScriptRunTime ---- Updated configuration."
            }
            else {
                Add-Content $LogFileForScript "$ScriptRunTime ---- Failed to copy sysmon items."
                exit
            }                     
        }
        else {
            Add-Content $LogFileForScript "$ScriptRunTime ---- Current Sysmon Config is Up To Date"
        }
    }
    # Sysmon is not installed, so install with config 
    else
    {
        # Copy sysmon locally, for install performance and incase network drops during install
        cmd.exe /c "copy /V $SysVolSysmonPE $LocalSysmonPE"
        cmd.exe /c "copy /V $SysVolSysmonConfig $LocalSysmonConfig"
        # Make sure copies where successful
        if((Test-Path $LocalSysmonPE) -and (Test-Path $LocalSysmonConfig) -and (get-authenticodesignature $LocalSysmonPE) -and ((get-item "\\example.nonexdom\sysvol\example.nonexdom\sysmon\sysmon64.exe").versioninfo.ProductName -eq "Sysinternals Sysmon"))
        {
            cmd.exe /c "$LocalSysmonPE -accepteula -i $LocalSysmonConfig"
            Add-Content $LogFileForScript "$ScriptRunTime ---- First install, or sysmon was removed completely at some point."
        }
        else {
            Add-Content $LogFileForScript "$ScriptRunTime ---- Failed to copy sysmon items."
            exit
        }
    }    
}
else{
    Add-Content $LogFileForScript "$ScriptRunTime ---- Failed to find sysmon items in sysvol."
}
# Ensure sysmon services are running
try{
    $SysmonService = get-service -Name $SysmonService -ErrorAction STOP
    $SysmonDrvService = get-service -Name "sysmondrv" -ErrorAction STOP
    if($SysmonService.Status -ne "running"){Add-Content $LogFileForScript "$ScriptRunTime ---- Service was stopped, starting sysmon PE."; start-service -name "sysmon" -ErrorAction Stop}
    if($SysmonDrvService.Status -ne "running"){Add-Content $LogFileForScript "$ScriptRunTime ---- Driver was stopped, starting sysmon driver.";start-service -name "sysmondrv" -ErrorAction Stop}
}
catch{
    Add-Content $LogFileForScript "$ScriptRunTime ---- Failed restarting and or getting status of sysmon services."
    exit
}

}

Function Get-RegistryKeyTimestamp {
    <#
        .SYNOPSIS
            Retrieves the registry key timestamp from a local or remote system.

        .DESCRIPTION
            Retrieves the registry key timestamp from a local or remote system.

        .PARAMETER RegistryKey
            Registry key object that can be passed into function.

        .PARAMETER SubKey
            The subkey path to view timestamp.

        .PARAMETER RegistryHive
            The registry hive that you will connect to.

            Accepted Values:
            ClassesRoot
            CurrentUser
            LocalMachine
            Users
            PerformanceData
            CurrentConfig
            DynData

        .NOTES
            Name: Get-RegistryKeyTimestamp
            Author: Boe Prox
            Version History:
                1.0 -- Boe Prox 17 Dec 2014
                    -Initial Build

        .EXAMPLE
            $RegistryKey = Get-Item "HKLM:\System\CurrentControlSet\Control\Lsa"
            $RegistryKey | Get-RegistryKeyTimestamp | Format-List

            FullName      : HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
            Name          : Lsa
            LastWriteTime : 12/16/2014 10:16:35 PM

            Description
            -----------
            Displays the lastwritetime timestamp for the Lsa registry key.

        .EXAMPLE
            Get-RegistryKeyTimestamp -Computername Server1 -RegistryHive LocalMachine -SubKey 'System\CurrentControlSet\Control\Lsa' |
            Format-List

            FullName      : HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
            Name          : Lsa
            LastWriteTime : 12/17/2014 6:46:08 AM

            Description
            -----------
            Displays the lastwritetime timestamp for the Lsa registry key of the remote system.

        .INPUTS
            System.String
            Microsoft.Win32.RegistryKey

        .OUTPUTS
            Microsoft.Registry.Timestamp
    #>
    [OutputType('Microsoft.Registry.Timestamp')]
    [cmdletbinding(
        DefaultParameterSetName = 'ByValue'
    )]
    Param (
        [parameter(ValueFromPipeline=$True, ParameterSetName='ByValue')]
        [Microsoft.Win32.RegistryKey]$RegistryKey,
        [parameter(ParameterSetName='ByPath')]
        [string]$SubKey,
        [parameter(ParameterSetName='ByPath')]
        [Microsoft.Win32.RegistryHive]$RegistryHive,
        [parameter(ParameterSetName='ByPath')]
        [string]$Computername
    )
    Begin {
        #region Create Win32 API Object
        Try {
            [void][advapi32]
        } Catch {
            #region Module Builder
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('RegAssembly')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('RegistryTimeStampModule', $False)
            #endregion Module Builder

            #region DllImport
            $TypeBuilder = $ModuleBuilder.DefineType('advapi32', 'Public, Class')

            #region RegQueryInfoKey Method
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'RegQueryInfoKey', #Method Name
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                [IntPtr], #Method Return Type
                [Type[]] @(
                    [Microsoft.Win32.SafeHandles.SafeRegistryHandle], #Registry Handle
                    [System.Text.StringBuilder], #Class Name
                    [UInt32 ].MakeByRefType(),  #Class Length
                    [UInt32], #Reserved
                    [UInt32 ].MakeByRefType(), #Subkey Count
                    [UInt32 ].MakeByRefType(), #Max Subkey Name Length
                    [UInt32 ].MakeByRefType(), #Max Class Length
                    [UInt32 ].MakeByRefType(), #Value Count
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Security Descriptor Size
                    [long].MakeByRefType() #LastWriteTime
                ) #Method Parameters
            )

            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            )

            $FieldValueArray = [Object[]] @(
                'RegQueryInfoKey', #CASE SENSITIVE!!
                $True
            )

            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @('advapi32.dll'),
                $FieldArray,
                $FieldValueArray
            )

            $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
            #endregion RegQueryInfoKey Method

            [void]$TypeBuilder.CreateType()
            #endregion DllImport
        }
        #endregion Create Win32 API object
    }
    Process {
        #region Constant Variables
        $ClassLength = 255
        [long]$TimeStamp = $null
        #endregion Constant Variables

        #region Registry Key Data
        If ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            #Get registry key data
            $RegistryKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $Computername).OpenSubKey($SubKey)
            If ($RegistryKey -isnot [Microsoft.Win32.RegistryKey]) {
                Throw "Cannot open or locate $SubKey on $Computername"
            }
        }

        $ClassName = New-Object System.Text.StringBuilder $RegistryKey.Name
        $RegistryHandle = $RegistryKey.Handle
        #endregion Registry Key Data

        #region Retrieve timestamp
        $Return = [advapi32]::RegQueryInfoKey(
            $RegistryHandle,
            $ClassName,
            [ref]$ClassLength,
            $Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$TimeStamp
        )
        Switch ($Return) {
            0 {
               #Convert High/Low date to DateTime Object
                $LastWriteTime = [datetime]::FromFileTime($TimeStamp)

                #Return object
                $Object = [pscustomobject]@{
                    FullName = $RegistryKey.Name
                    Name = $RegistryKey.Name -replace '.*\\(.*)','$1'
                    LastWriteTime = $LastWriteTime
                }
                $Object.pstypenames.insert(0,'Microsoft.Registry.Timestamp')
                $Object
            }
            122 {
                Throw "ERROR_INSUFFICIENT_BUFFER (0x7a)"
            }
            Default {
                Throw "Error ($return) occurred"
            }
        }
        #endregion Retrieve timestamp
    }
}

main

exit
