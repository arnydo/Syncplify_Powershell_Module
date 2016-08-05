function Connect-Syncplify {

    <#
    .SYNOPSIS
        Used to establish an initial connection to the Syncplify REST API
    .EXAMPLE
    PS>>Connect-Syncplify -Server SyncplifyServer01.MyDomain.Com -Port 4443
    .PARAMETER Server
        Name of server to connect to
    .PARAMETER Username
        Username with access to API
    .PARAMETER Password
        Password for specified username
    #>

    [CmdletBinding()]
    param(
    [Parameter(mandatory=$true)]
    [ValidateScript({ test-Connection $_ -quiet -count 1})]
    [string]$Server,
    [string]$Port = '4443',
    [string]$VirtualServer = 'default',
    [string]$User,
    [string]$Password
    )

    ## Declares the global variable to store the url of the server to be authenticated with
    $global:url = "https://$($server):$($port)/smserver-$($VirtualServer)"

    ## Checks if the username or password is not present and prompt for secure credentials
    if ([string]::IsNullOrEmpty($User) -or [string]::IsNullOrEmpty($Password)){
        $credentials = (get-credential)
        $user = $credentials.UserName
        $password = $credentials.GetNetworkCredential().Password
    }

    ## Concatenates the username and password into a base64 encoded string
    $userpass = $user+":"+$Password
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($userpass)
    $encoded = [system.convert]::ToBase64String($bytes)

    ## Defines the header section of the API call
    $headers = @{
        Authorization = "Basic $encoded"
        }

    ## Begins the main call to the server with supplied information
    try {

    ## Sends auth request to the server and stores the result in the variable $SyncplifyAuthResult for use by other functions
    Write-Verbose -Message "Invoke-RestMethod -Method get -Uri $($url)/auth -ContentType application/json -Headers $($headers)"
    $global:SyncplifyAuthResult = Invoke-RestMethod -Method get -Uri $url"/auth" -ContentType "application/json" -Headers $headers

        } ## End try

  catch {

             ## Checks to see if the authentication failed due to incorrect connection details
             if ( $($_.Exception.Message) -match "400") { Write-Error -Message "Failed to authenticate with $server. Please verify connection details and try again." } else { $_.Exception.Message }

             ## If authentication fails the function stops processing
             return

        } ## End Catch

        ## Upon successful connection, the following is written to the host
        Write-Host -BackgroundColor DarkGreen "Connected to Syncplify Server: $url"

} ## End function Connect-Syncplify

function Disconnect-Syncplify {

    <#
    .SYNOPSIS
        Used to disconnect from the Syncplify REST API
    .EXAMPLE
    PS>>Disconnect-Syncplify
    #>

    [CmdletBinding()]
    param()

    ## Begin processing
    try {

    ## Sends disconnect request to $url
    Invoke-RestMethod -Method get -Uri $url"/sms.Disconnect" -ContentType "application/json" -Headers @{"Authorization" = "Bearer $($SyncplifyAuthResult.access_token)"}

    } catch {

        ## Checks to see if there were no active connections to $url
        if ($($_.Exception.Message) -match "403") { Write-Error -Message "There is not an active connection to $Url" }

        ## If error is cought the function stops processing
        return

    }

    ## Upon successful disconnection, the following is written to the host
    Write-Host -BackgroundColor DarkGreen "Disconnected from $url"


} ## End function Disconnect-Syncplify

function Get-SyncplifyConfig {

    <#
    .SYNOPSIS
        Used to retrieve the full configuration of the Syncplify server
    .EXAMPLE
    PS>>Get-SyncplifyConfig
    #>

    [CmdletBinding()]
    param()

    ## Declares the $body variable as JSON array containing a single empty object
    $body = "[{}]"

    ## Begin processing
    try {

    ## Send POST to $url
    $Result = Invoke-RestMethod -Method POST -uri $url"/sms.LoadConf" -ContentType "application/json" -body $body -Headers @{"Authorization" = "Bearer $($SyncplifyAuthResult.access_token)"}

    }

    ## Checks for any errors
    catch {
            ## If error 403 received, the following is written to the host
            if ($_.Exception.MEssage -match "403") {Write-Error "ACCESS DENIED: You must authenticate with the Syncplify server before proceeding."}

            ## Stops the processing
            return
    }

    ## Returns the config
    return $Result[0].Result

} ## End function Get-SyncplifyConfig

function Set-SyncplifyConfig {

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({ test-path -Path $_ })]
    [string]$Path
    )

    $body = Get-Content -Path $Path | ConvertFrom-Json
    $Body = ConvertTo-Json -InputObject @($body)


    try {

    $result = Invoke-RestMethod -Method POST -uri $url"/sms.SaveConf" -ContentType "application/json" -body $Body -Headers @{"Authorization" = "Bearer $($SyncplifyAuthResult.access_token)"}

    } catch {

            ## If error 403 received, the following is written to the host
            if ($_.Exception.MEssage -match "403") {Write-Error "ACCESS DENIED: You must authenticate with the Syncplify server before proceeding."}

            ## Stops the processing
            return

    }

    Write-Host -BackgroundColor DarkGreen "Configuration has been saved"

} ## End function Set-SyncplifyConfig

function Get-SyncplifyUser {

    <#
    .SYNOPSIS
        Used to retrieve a user or all users from the Syncplify Server
    .EXAMPLE
    PS>>Get-SyncplifyUser -User 'User@domain.com'
    .EXAMPLE
    PS>>Get-SyncplifyUser -All
    .PARAMETER User
        Username of user to retrieve
    .PARAMETER All
        Switch used to retrieve all users. Cannot be used in conjunction with the 'User' parameter
    #>

    [CmdletBinding()]
    param(
    [Parameter(ParameterSetName='SingleUser')]
    [string]$User,
    [Parameter(ParameterSetName='AllUsers')]
    [switch]$All
    )

    ## Declares the header section
    $headers = @{
    Authorization = "Bearer $($SyncplifyAuthResult.access_token)"
    Accept = "*/*"
    }

    try {

        ## If the -All parameter is used:
        if ($PSCmdlet.ParameterSetName -eq 'AllUsers') {

            $body = "[{}]"
            $Result = Invoke-RestMethod -Method POST -uri $url"/sms.ReadUserList" -ContentType "application/json" -body $body -Headers $headers
            }

        ## If the -User parameter is used:
        if ($PSCmdlet.ParameterSetName -eq 'SingleUser') {
            $body = ,@{AUName = "$user"}
            $body = ConvertTo-Json -InputObject @($body)
            $Result = Invoke-RestMethod -Method POST -uri $url"/sms.LoadUser" -ContentType "application/json" -body $body -Headers $headers
            }

        } catch {

            ## Checks for errors
            if ($_.Exception.MEssage -match "403") {Write-Error "ACCESS DENIED: You must authenticate with the Syncplify server before proceeding."}

            ## Stops processing
            return
        }

        ## Returns the result of the request
        return $Result = New-Object PSObject -Verbose $Result[0].Result

} ## End function Get-SyncplifyUser

function Get-SyncplifyVFS {

    <#
    .SYNOPSIS
        Used to retrieve VFS info from the Syncplify server
    .EXAMPLE
    PS>>Get-SyncplifyVFS -All
    .EXAMPLE
    PS>>Get-SyncplifyVFS -VFS
    .PARAMETER Server
        Name of server to connect to
    .PARAMETER Username
        Username with access to API
    .PARAMETER Password
        Password for specified username
    #>

    [CmdletBinding()]
    param(
    [parameter(ParameterSetName='AllVFS')]
    [switch]$All,
    [Parameter(ParameterSetName='SingleVFS')]
    [String]$VFS
    )

    ## Defines header section
    $headers = @{
    Authorization = "Bearer $($SyncplifyAuthResult.access_token)"
    Accept = "*/*"
    }

    try{

    ## If -All switch is used:
    if ($PSCmdlet.ParameterSetName -eq 'AllVFS') {

    ## Defines body as a JSON array with a single empty item
    $body = "[{}]"
    $Result = Invoke-RestMethod -Method POST -uri $url"/sms.readVFSlist" -body $body -ContentType "application/json" -Headers $headers

    }

    ## If -SingleVFS is used:
    if ($PSCmdlet.ParameterSetName -eq 'SingleVFS') {

    ## Defines body as a JSON array containing the vfs id
    $Body = ,@{Aitem = "$vfs"}
    $body = ConvertTo-Json -InputObject @($body)
    $Result = Invoke-RestMethod -Method POST -uri $url"/sms.loadVFS" -body $body -ContentType "application/json" -Headers $headers

    }


    } catch {

            ## Checks for errors
            if ($_.Exception.MEssage -match "403") {Write-Error "ACCESS DENIED: You must authenticate with the Syncplify server before proceeding."}
            else {$_.Exception.Message}

            ## Stops processing
            return

    }

    return $Result = New-Object PSObject -Verbose $Result[0].Result

} ## End function Get-SyncplifyVFS

function Remove-SyncplifyUser {

    Param (
    [Parameter(Mandatory)]
    [string]$User
    )

    ## Define header section
    $headers = @{
    Authorization = "Bearer $($SyncplifyAuthResult.access_token)"
    Accept = "*/*"
    }

    ## Beging processing
    try {

    ## Define body as a single JSON array containin the Aitem object
    $body = ,@{AUName = "$user"}
    ## Converts the Body to JSON
    $Body = ConvertTo-Json -InputObject @($body)
    ## Sends request to server
    $Result = Invoke-RestMethod -Method POST -uri $url"/sms.DeleteUser" -ContentType "application/json" -body $Body -Headers $headers

    } catch {

        ## Checks for auth errors
        if ($_.Exception.Message -match "403") {Write-Error "ACCESS DENIED: You must authenticate with the Syncplify server before proceeding."}

        ## Stop processing
        return

    }

    ## Checks to see if the result is equal to 1 (Success)
    if ($Result[1].Result -eq 1) { Write-Host -BackgroundColor DarkGreen "Successfully deleted $user" }
    else {Write-Error "Error deleting $user. Does this user exist?" }
} ## End function Delete-SyncplifyUser

function Get-SyncplifyPassUtil {

    <#
    .SYNOPSIS
        Used to generate and verify passwords
    .EXAMPLE
    PS>>$generated = Get-SyncplifyPassUtil -Password '123' -Command Generate
    .EXAMPLE
    PS>>Get-SyncplifyPassUtil -salt $generated.salt -PassHash $generated.PassHash -Password '123' -Command Verify
    .PARAMETER Password
        Password to generate a hash for or verify
    .PARAMETER Command
        Generate or Verify
    .PARAMETER Salt
        Salst of password
    .PARAMETER PassHash
        Hashed password
    .PARAMETER VServer
        Virtual server to verify password against
    #>

    [CmdletBinding()]
    param(
    [parameter(mandatory)]
    [string]$Password,
    [parameter(mandatory)]
    [ValidateSet('Generate','Verify')]
    [string]$Command,
    [string]$salt,
    [string]$PassHash,
    [string]$VServer = 'default'
    )

    ## Define header section
    $headers = @{
    Authorization = "Bearer $($SyncplifyAuthResult.access_token)"
    Accept = "*/*"
    }

    ## Start processing
    try {

    ## Switch based on Command parameter
    switch ($Command) {

        'Generate' {
    $body = ,@{command = "generate";password = "$Password"}
    $body = ConvertTo-Json -InputObject @($body)

    $global:hash = Invoke-RestMethod -Method POST -uri $url"/sms.PassUtil" -ContentType "application/json" -body $Body -Headers $headers
    return $hash[0].result
    }

        'Verify' {
    $body = ,@{command = "verify";password = "$Password";salt = "$Salt";PassHash = "$PassHash";Vserver = "$VServer"}
    $body = ConvertTo-Json @($body)
    $Result = Invoke-RestMethod -Method POST -uri $url"/sms.PassUtil" -ContentType "application/json" -body $Body -Headers $headers

    }
    }

    } catch {if ($_.Exception.MEssage -match "403") {Write-Error "ACCESS DENIED: You must authenticate with the Syncplify server before proceeding."}
    }

    return Write-Host -BackgroundColor DarkGreen "$($Result[0].Result.ResultMsg)"

} ## End function Get-SyncplifyPassUtil

function Get-SyncplifyNode {

    [CmdletBinding()]
    param()

    ## Define header section
    $headers = @{
    Authorization = "Bearer $($SyncplifyAuthResult.access_token)"
    Accept = "*/*"
    }

    ## Start processing
    try {

    $body = ,@{}
    $body = ConvertTo-Json -InputObject @($body)

    $Result = Invoke-RestMethod -Method POST -uri $url"/sms.ReadNodeList" -ContentType "application/json" -body $Body -Headers $headers


    }

    ## Catch any errors
    catch {if ($_.Exception.MEssage -match "403") {Write-Error "ACCESS DENIED: You must authenticate with the Syncplify server before proceeding."}
    }

    ## Return result
    return $Result = New-Object PSObject -Verbose $Result[0].Result

} ## End function Get-SyncplifyNode

function Get-SyncplifySessions {

    [CmdletBinding()]
    param(
    [switch]$All,
    [String]$NodeID
    )

    $headers = @{
    Authorization = "Bearer $($SyncplifyAuthResult.access_token)"
    Accept = "*/*"
    }

    ## Begin processing
    try {

    ## Declares the JSON array to be used as the body
    $nodelist = @"
    [
        {
            "nodes": [

                     ]
        }
    ]
"@ | Convertfrom-json

    ## Retrieves a list of current nodes for the virtual server
    $nodes = Get-SyncplifyNode

    ## For each node retrieved it will be added to the $Nodelist JSON array
    foreach ($node in $nodes[0]) {
        $nodelist[0].nodes += $node._id
    }

    ## Converts the array to JSON
    $body = ConvertTo-Json @($nodelist)

    ## Sends the API request to the server
    $Result = Invoke-RestMethod -Method POST -uri $url"/sms.GetSession" -ContentType "application/json" -body $body -Headers $headers


    }
    ## Checks for errors
    catch {if ($_.Exception.Message -match "403") {Write-Error "ACCESS DENIED: You must authenticate with the Syncplify server before proceeding."}}

    ## Returns a list of active sessions
    return $Result = New-Object PSObject -Verbose $Result[0].Result

} ## End function Get-SyncplifySessions

## ALIASES
New-Alias -Name Connect-SM -Value Connect-Syncplify
New-Alias -Name Disconnect-SM -Value Disconnect-Syncplify
New-Alias -Name Get-SMConfig -Value Get-SyncplifyConfig
New-Alias -Name Set-SMConfig -Value Set-SyncplifyConfig
New-Alias -Name Get-SMUser -Value Get-SyncplifyUser
New-Alias -Name Get-SMVFS -Value Get-SyncplifyVFS
New-Alias -Name Remove-SMUser -Value Remove-SyncplifyUser
New-Alias -Name Get-SMPassUtil -Value Connect-Syncplify
New-Alias -Name Get-SMNode -Value Connect-Syncplify
New-Alias -Name Get-SMSessions -Value Get-SyncplifySessions