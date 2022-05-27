Function Set-UACValueTable {
       
    # Creates a Hash of Name/Value pairs for UserAccountCrontrol values
    $UACValueTable = New-Object HashTable
    $UACValueTable.Add("SCRIPT",1)
    $UACValueTable.Add("ACCOUNTDISABLE",2)
    $UACValueTable.Add("HOMEDIR_REQUIRED",8) 
    $UACValueTable.Add("LOCKOUT",16)
    $UACValueTable.Add("PASSWD_NOTREQD",32)
    $UACValueTable.Add("PASSWD_CANT_CHANGE",64)
    $UACValueTable.Add("ENCRYPTED_TEXT_PWD_ALLOWED",128)
    $UACValueTable.Add("TEMP_DUPLICATE_ACCOUNT",256)
    $UACValueTable.Add("NORMAL_ACCOUNT",512)
    $UACValueTable.Add("INTERDOMAIN_TRUST_ACCOUNT",2048)
    $UACValueTable.Add("WORKSTATION_TRUST_ACCOUNT",4096)
    $UACValueTable.Add("SERVER_TRUST_ACCOUNT",8192)
    $UACValueTable.Add("DONT_EXPIRE_PASSWORD",65536) 
    $UACValueTable.Add("MNS_LOGON_ACCOUNT",131072)
    $UACValueTable.Add("SMARTCARD_REQUIRED",262144)
    $UACValueTable.Add("TRUSTED_FOR_DELEGATION",524288) 
    $UACValueTable.Add("NOT_DELEGATED",1048576)
    $UACValueTable.Add("USE_DES_KEY_ONLY",2097152) 
    $UACValueTable.Add("DONT_REQ_PREAUTH",4194304) 
    $UACValueTable.Add("PASSWORD_EXPIRED",8388608) 
    $UACValueTable.Add("TRUSTED_TO_AUTH_FOR_DELEGATION",16777216) 
    $UACValueTable.Add("PARTIAL_SECRETS_ACCOUNT",67108864)
 
    # Enuymerates the Hash and sort it by values
    $UACValueTable = $UACValueTable.GetEnumerator() | Sort-Object -Property Value 
 
    # Return the Hash
    return $UACValueTable
}
 
Function Get-UACFlags {
    [CmdletBinding()]param(
            [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
            [ValidateNotNullOrEmpty()]
            $UAC
        ) 
    # Ensure variables are empty before use 
    $Flags = @()
    $StringToReturn = ""
 
    # Query the Hash for Names corresponding to UAC value
    Set-UACValueTable | foreach {
            $binaryAnd = $_.value -band $UAC
            if ($binaryAnd -ne "0") { 
            $Flags += $_.Name
        }
    }
    # Store everything as a string with names split by ':'
    $StringToReturn = $Flags -join ':'
 
    # return the translation
    return $StringToReturn
}
