[CmdletBinding()]
param(
    [string]$DatabaseHost = '192.168.20.29',
    [int]$DatabasePort = 8060,
    [string]$DatabaseName = 'AtlasTI',
    [string]$DatabaseUsername = 'atlas_ti',
    [string]$LdapHost = '192.168.20.14',
    [string]$LdapSecondaryHost = '',
    [int]$LdapPort = 636,
    [string]$LdapUserIdFormat = '{0}',
    [string]$AdminLogin = 'icaro.admin',
    [string]$AdminName = 'Administrador Atlas TI',
    [string]$AdminEmail = 'icaro.admin@empresa.local',
    [string]$ApiUrl = 'http://localhost:5225'
)

$ErrorActionPreference = 'Stop'
$managedEnvironmentNames = @(
    'DOTNET_CLI_HOME','NUGET_PACKAGES','NUGET_HTTP_CACHE_PATH','DOTNET_SKIP_FIRST_TIME_EXPERIENCE','DOTNET_CLI_TELEMETRY_OPTOUT',
    'ConnectionStrings__AtlasTi','Jwt__SigningKey','ASPNETCORE_URLS','ASPNETCORE_ENVIRONMENT',
    'Ldap__Host','Ldap__SecondaryHost','Ldap__Port','Ldap__UserIdFormat',
    'DatabaseBootstrap__InitializeOnStartup','DatabaseBootstrap__AdminExternalId','DatabaseBootstrap__AdminName','DatabaseBootstrap__AdminEmail'
)
$previousEnvironment = @{}
foreach ($name in $managedEnvironmentNames) { $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$apiDirectory = Join-Path $PSScriptRoot 'api'
$projectFile = Join-Path $apiDirectory 'api.csproj'
if (-not (Test-Path $projectFile)) { throw "Projeto da API não encontrado: $projectFile" }

# Keep SDK first-run files and NuGet caches beside the deliverable so a locked
# Windows profile does not prevent dotnet from starting.
$env:DOTNET_CLI_HOME = Join-Path $PSScriptRoot '.dotnet-cli'
$env:NUGET_PACKAGES = Join-Path $PSScriptRoot '.nuget-packages'
$env:NUGET_HTTP_CACHE_PATH = Join-Path $PSScriptRoot '.nuget-http-cache'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'

$sdk = & dotnet --list-sdks 2>$null
if ($LASTEXITCODE -ne 0 -or -not ($sdk | Where-Object { $_ -match '^10\.' })) {
    throw 'Instale o .NET 10 SDK antes de iniciar a API.'
}

Write-Host "Atlas TI vai se conectar ao MariaDB em ${DatabaseHost}:${DatabasePort}, base $DatabaseName."
Write-Host "LDAPS configurado para $LdapHost`:$LdapPort. A senha do banco será solicitada sem ser exibida."
$credential = Get-Credential -UserName $DatabaseUsername -Message 'Informe a senha MariaDB configurada no servidor Docker.'
if (-not $credential) { throw 'Inicialização cancelada: senha do banco não informada.' }

$builder = [System.Data.Common.DbConnectionStringBuilder]::new()
$builder['Server'] = $DatabaseHost
$builder['Port'] = $DatabasePort
$builder['Database'] = $DatabaseName
$builder['User ID'] = $credential.UserName
$builder['Password'] = $credential.GetNetworkCredential().Password
$builder['SslMode'] = 'Preferred'

$keyBytes = [byte[]]::new(64)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($keyBytes)
$signingKey = [Convert]::ToBase64String($keyBytes)
$rng.Dispose()

$env:ConnectionStrings__AtlasTi = $builder.ConnectionString
$env:Jwt__SigningKey = $signingKey
$env:ASPNETCORE_URLS = $ApiUrl
$env:ASPNETCORE_ENVIRONMENT = 'Development'
$env:Ldap__Host = $LdapHost
$env:Ldap__SecondaryHost = $LdapSecondaryHost
$env:Ldap__Port = "$LdapPort"
$env:Ldap__UserIdFormat = $LdapUserIdFormat
$env:DatabaseBootstrap__InitializeOnStartup = 'true'
$env:DatabaseBootstrap__AdminExternalId = $AdminLogin
$env:DatabaseBootstrap__AdminName = $AdminName
$env:DatabaseBootstrap__AdminEmail = $AdminEmail

Push-Location $apiDirectory
try {
    Write-Host 'Restaurando dependências da API.'
    & dotnet restore $projectFile --configfile (Join-Path $apiDirectory 'NuGet.Config')
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao restaurar dependências NuGet.' }

    Write-Host 'Iniciando API e aplicando o schema se a base ainda estiver vazia.'
    & dotnet run --no-restore --project $projectFile --no-launch-profile
    if ($LASTEXITCODE -ne 0) { throw 'A API encerrou com erro. Verifique acesso à base MariaDB e ao servidor LDAPS.' }
}
finally {
    Pop-Location
    foreach ($name in $managedEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    Remove-Item Env:DOTNET_CLI_HOME,Env:NUGET_PACKAGES,Env:NUGET_HTTP_CACHE_PATH,Env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE,Env:DOTNET_CLI_TELEMETRY_OPTOUT -ErrorAction SilentlyContinue
    $builder.Clear()
    $credential = $null
    [Array]::Clear($keyBytes, 0, $keyBytes.Length)
}
