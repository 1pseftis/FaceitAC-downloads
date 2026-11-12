#requires -Version 5.1
<#
Downloads and verifies setup, then starts its agreement/tasks/activation flow.
The key is checked before installing into Program Files and creating shortcuts.
For a download without launching the app:
  & ([scriptblock]::Create((Invoke-RestMethod 'https://1pseftis.github.io/FaceitAC-downloads/install.ps1'))) -NoRun
-InstallDirectory overrides only the download/staging cache, not the final install path.
#>
[CmdletBinding()]
param(
    [switch]$NoRun,
    [string]$InstallDirectory,
    [uri]$ManifestUrl = 'https://github.com/1pseftis/FaceitAC-downloads/releases/latest/download/release.json'
)

# Public trust only. Keep this reviewed pin synchronized with the client ring.
function Get-FaceitAcTrustedReleaseKeys {
    $ring = @'
{"schema":1,"keys":[{"key_id":"release-2026-01","modulus":"uCfbfdGQq2gl//kbUHcD2Mkvqhmnq8TnErYsVZNTZR7WYWoyHUIicpo2jmsziBCqISKe1tBo4r9yh6b6M51EoTKh5LIUzUaG7FZBHH9DZpQ1xbYZNeOnbISl+sb8W2J6Hm2wIBkqsu7SKbtvW5Fl6YlTCxFmrASu8y2Nq/M7FKbhiu60YXKdKOAbPFJc5IOHfzWmij8vaySiT3bgfzH2Blh3s7GmRVk8KlPnRpgGn227vRiVYkMzs1aQ7t9rvwFmStmsFranYVlSBIZ1YPafrl1r3wc95M5Kce7nvBVuWKerqzzRxLfPq3RtOo9GhNyXfGA7o3qM6LVt8y0ZwILu1OUNHlLRew30FNCC+6EaAJB+NMcqBEqIxY/G7Kh89G0jHFUZZTm5W4UetUMbr5hfRUd5SVmgz4AsZaecIkvtn4fPGKgO5VTwoj/dAO62w7GI6NkmTCGscf/ljNfYXjwCrdxXP14m6qaMid4Ayx95T7pT/TQs4PhekzqP79UIt7uR","exponent":"AQAB"},{"key_id":"release-2026-02","modulus":"xBdzKAHK5lZEE7XwEZcVDgu8oaVk9MSiAWU7XXAEjxw5yf9noUCMXEFln9Ykvsi/Ncsfpxbo8v/9YExrXMUHcui0SObJQYLuM6UtSL3AbmjRLAvSGA+wNzSrEMnbaRglQBf4c82x5HM0GN9W/iRKzJbGCTxgBe57LfWQatIWuT/RKyx1csEPrAjE76n9LrZWX7s+kgCMqFD7izRa7jnzAsQCR1GsAOTCKF2A/70aStax8ErzONLVDPOAGSbePCxZ50DysXUcPKKIyOb6ZSZ7+kYoYWy3URzJfvMVD2nKBIq9j1+3AYuaAhC/Wtoe+UFsT03xx4gbOOdcIIrn9I8+SgoTQsbpCxvJVo2x6Vj8lB/NXCO+L/qXSve5m+FPsQUeNMmRSTq28ELuCJFvka89HCHiHgkevRe1bXCvIKWuVRlhSyyGvOSAKADFni7KfuDRsCe/X7ohCOkr7cTQlHMJwznl6q1wEEFZ3IDcHzsafEkjsHgfT7jRrj12Rt1JkPW9","exponent":"AQAB"},{"key_id":"release-2026-recovery-01","modulus":"zZ/20y+IBgG73kiuk2iSK4Nmgx+pIGpjBwu7GUTBM+RoYK39SJHgvWqfgEC+ae/swvOucUZ/4e3Fp//0U5AVBSdvCTcoeAI/qQzaphQ3wC+qPhDFpJwaXYeO8mPdp1B8vcn5mlJ5El6f0b9aRNjUKJJcm6Q4Y0eNXFml1b6jtebMNzSQfvp2GwOhp+WH4vBRTMi4EyZ9ZoTswgqsKL4ll/VqkVU8AYRdjeWaic1Jj1Y8K9tobu8r8HKLknHbDta2x+7VSzgGMht+Fz0xvSU38IYHWSB2AZHjfneUWN0oLY5SRDaTXj3aY9qnmST4wZ8r2DemLhLNEASUbaXrnEM8ziDXP/H7qJV9m2kab9Gv5Esz9/VCFTIm6Vh667FDRIaKXojNpFupYFU4fhTyGzRihoMLW7fm3RuPw7F1mkb+j7WKm9sM5ASRvuPisEUiFNw7BWLa/DuX0K6uerVMdceEsAVUhaxRsHps1t029TzEGzkqSJbAPwdc3vfSVxyx2ykv","exponent":"AQAB"}]}
'@ | ConvertFrom-Json
    return @($ring.keys)
}

function Assert-FaceitAcReleaseSignature {
    param([string]$Json, $Manifest)
    if ([Text.Encoding]::UTF8.GetByteCount($Json) -gt 16384 -or
        $Json -cnotmatch '\A\s*\{\s*"[a-z0-9_]+"\s*:\s*"[^"\\\x00-\x1f]*"\s*(?:,\s*"[a-z0-9_]+"\s*:\s*"[^"\\\x00-\x1f]*"\s*)*\}\s*\z' -or
        [regex]::Matches($Json, '"[a-z0-9_]+"\s*:').Count -ne 9) { throw 'A canonical signed release manifest is required.' }
    $fields = @('version','commit','package_url','sha256','installer_url','installer_sha256','signature_algorithm','key_id','signature')
    if (@($Manifest.PSObject.Properties).Count -ne 9) { throw 'The signed release schema is incomplete.' }
    foreach ($property in $Manifest.PSObject.Properties) {
        if ($fields -cnotcontains $property.Name -or $property.Value -isnot [string]) { throw 'Unexpected signed release fields.' }
    }
    if ($Manifest.signature_algorithm -cne 'RS256' -or $Manifest.version -cnotmatch '\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?\z' -or
        $Manifest.commit -cnotmatch '\A[0-9a-f]{40}\z' -or $Manifest.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        $Manifest.installer_url -cne $Manifest.package_url -or $Manifest.installer_sha256 -cne $Manifest.sha256) { throw 'The signed release identities are invalid.' }
    $key = @(Get-FaceitAcTrustedReleaseKeys | Where-Object { $_.key_id -ceq $Manifest.key_id })
    if ($key.Count -ne 1) { throw 'This release signing key is not trusted. Obtain a reviewed newer bootstrap.' }
    $parameters = New-Object Security.Cryptography.RSAParameters
    $parameters.Modulus = [Convert]::FromBase64String($key[0].modulus)
    $parameters.Exponent = [Convert]::FromBase64String($key[0].exponent)
    $signature = [Convert]::FromBase64String($Manifest.signature)
    if ($signature.Length -ne $parameters.Modulus.Length -or [Convert]::ToBase64String($signature) -cne $Manifest.signature) { throw 'Invalid release signature encoding.' }
    $text = @('FaceitAC.ReleaseManifest.v1',$Manifest.key_id,$Manifest.version,$Manifest.commit,$Manifest.package_url,$Manifest.sha256,$Manifest.installer_url,$Manifest.installer_sha256,'') -join "`n"
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
    $rsa.PersistKeyInCsp = $false
    try {
        $rsa.ImportParameters($parameters)
        if (-not $rsa.VerifyData([Text.Encoding]::UTF8.GetBytes($text), [Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'), $signature)) { throw 'The release signature is invalid. Nothing was downloaded or launched.' }
    } finally { $rsa.Dispose() }
}

function Get-FaceitAcSha256 {
    param([System.IO.Stream]$Stream)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

function Test-FaceitAcFramework {
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $baseKey = $null
        $frameworkKey = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $frameworkKey = $baseKey.OpenSubKey('SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full')
            if ($null -ne $frameworkKey -and [int]$frameworkKey.GetValue('Release', 0) -ge 528040) { return $true }
        }
        finally {
            if ($null -ne $frameworkKey) { $frameworkKey.Dispose() }
            if ($null -ne $baseKey) { $baseKey.Dispose() }
        }
    }
    return $false
}

function Invoke-FaceitAcRequest {
    param([uri]$Url, [string]$Destination)
    $previousProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        if ([string]::IsNullOrEmpty($Destination)) { return Invoke-WebRequest -Uri $Url.AbsoluteUri -UseBasicParsing }
        Invoke-WebRequest -Uri $Url.AbsoluteUri -UseBasicParsing -OutFile $Destination
    }
    finally { [System.Net.ServicePointManager]::SecurityProtocol = $previousProtocol }
}

function Get-FaceitAcPackageUri {
    param([string]$Value, [switch]$InstallerOnly)
    $packageUrl = $null
    if (-not [uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$packageUrl) -or
        $packageUrl.Scheme -ne 'https' -or $packageUrl.Host -ne 'github.com' -or
        -not $packageUrl.IsDefaultPort -or -not [string]::IsNullOrEmpty($packageUrl.UserInfo) -or
        $packageUrl.AbsolutePath -cnotmatch '\A/1pseftis/FaceitAC-downloads/releases/download/[^/]+/(?:FACEITInstaller_64\.exe|faceitclient\.exe|FaceitAC-Windows\.zip)\z' -or
        -not [string]::IsNullOrEmpty($packageUrl.Query) -or -not [string]::IsNullOrEmpty($packageUrl.Fragment)) {
        throw 'The package URL must point to a versioned FACEITInstaller_64.exe, faceitclient.exe, or FaceitAC-Windows.zip release in 1pseftis/FaceitAC-downloads.'
    }
    if ($InstallerOnly -and -not $packageUrl.AbsolutePath.EndsWith('/FACEITInstaller_64.exe', [StringComparison]::Ordinal)) {
        throw 'installer_url must point to the versioned FACEITInstaller_64.exe release asset.'
    }
    return $packageUrl
}

function Expand-FaceitAcPackage {
    param([string]$PackagePath, [string]$VersionDirectory, [switch]$ExecutablePackage,
        [ValidateSet('faceitclient.exe', 'FACEITInstaller_64.exe')][string]$ExecutableName = 'faceitclient.exe')
    $archive = $null
    try {
        if ($ExecutablePackage) {
            $packageLength = (Get-Item -LiteralPath $PackagePath).Length
            if ($packageLength -le 0 -or $packageLength -gt 128MB) { throw 'The application download is empty or oversized.' }
            $expectedFiles = @($ExecutableName)
        }
        else {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
            # Accept the new one-file archive and the four-file v1.0 package.
            if ($archive.Entries.Count -eq 1 -and $archive.Entries[0].FullName -ceq 'faceitclient.exe') {
                $expectedFiles = @('faceitclient.exe')
            }
            else { $expectedFiles = @('FACEITInstaller_64.exe', 'FACEITInstaller_64.exe.config', 'START-HERE.txt', 'OFL.txt') }
            if ($archive.Entries.Count -ne $expectedFiles.Count) { throw 'The ZIP has an unexpected file list.' }
            $seen = @{}
            foreach ($entry in $archive.Entries) {
                if ($expectedFiles -cnotcontains $entry.FullName -or $seen.ContainsKey($entry.FullName) -or
                    $entry.Length -le 0 -or $entry.Length -gt 128MB) {
                    throw ('The ZIP contains an unexpected, empty, or oversized entry: {0}' -f $entry.FullName)
                }
                $seen[$entry.FullName] = $true
            }
        }

        if (Test-Path -LiteralPath $VersionDirectory) {
            # Never replace a cached executable another process might be using.
            $existing = @(Get-ChildItem -LiteralPath $VersionDirectory -Force)
            if ($existing.Count -ne $expectedFiles.Count) {
                throw "The cached version is incomplete or changed: $VersionDirectory. Move that folder aside and run the command again."
            }
            foreach ($name in $expectedFiles) {
                $existingFile = Join-Path $VersionDirectory $name
                if (-not (Test-Path -LiteralPath $existingFile -PathType Leaf)) { throw "The cached version is incomplete: $VersionDirectory" }
                if ($ExecutablePackage) { $expectedHash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash }
                else {
                    $entryStream = $archive.GetEntry($name).Open()
                    try { $expectedHash = Get-FaceitAcSha256 -Stream $entryStream }
                    finally { $entryStream.Dispose() }
                }
                if ((Get-FileHash -LiteralPath $existingFile -Algorithm SHA256).Hash -ne $expectedHash) {
                    throw "A cached file has changed: $existingFile. Move its version folder aside and run the command again."
                }
            }
        }
        else {
            $versionsDirectory = Split-Path -Parent $VersionDirectory
            New-Item -ItemType Directory -Path $versionsDirectory -Force | Out-Null
            $stagingDirectory = Join-Path $versionsDirectory ('.staging-' + [Guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $stagingDirectory | Out-Null
            if ($ExecutablePackage) { Copy-Item -LiteralPath $PackagePath -Destination (Join-Path $stagingDirectory $ExecutableName) }
            else {
                foreach ($entry in $archive.Entries) {
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $stagingDirectory $entry.FullName), $false)
                }
            }
            # Both resolved paths must stay immediate children of this cache.
            $safeParent = [IO.Path]::GetFullPath($versionsDirectory).TrimEnd('\') + '\'
            foreach ($candidate in @($stagingDirectory, $VersionDirectory)) {
                $resolved = [IO.Path]::GetFullPath($candidate)
                if (-not $resolved.StartsWith($safeParent, [StringComparison]::OrdinalIgnoreCase) -or
                    [IO.Path]::GetDirectoryName($resolved) -ne $safeParent.TrimEnd('\')) {
                    throw 'The staging path escaped its download cache.'
                }
            }
            [System.IO.Directory]::Move($stagingDirectory, $VersionDirectory)
        }
        return Join-Path $VersionDirectory $expectedFiles[0]
    }
    finally { if ($null -ne $archive) { $archive.Dispose() } }
}

function Invoke-FaceitAcInstall {
    $ErrorActionPreference = 'Stop'
    if ($env:OS -ne 'Windows_NT' -or [Environment]::OSVersion.Version.Major -lt 10) { throw 'This application requires Windows 10 or 11.' }
    if (-not (Test-FaceitAcFramework)) {
        throw '.NET Framework 4.8 or later is required. Install it from https://dotnet.microsoft.com/download/dotnet-framework/net48 and run this command again.'
    }
    if (-not $ManifestUrl.IsAbsoluteUri -or $ManifestUrl.Scheme -ne 'https') { throw 'The release manifest URL must use HTTPS.' }
    if ([string]::IsNullOrWhiteSpace($InstallDirectory)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'Windows LOCALAPPDATA was not found.' }
        $InstallDirectory = Join-Path $env:LOCALAPPDATA 'FaceitAC\bootstrap'
    }
    $cacheRoot = [IO.Path]::GetFullPath($InstallDirectory)
    $downloadsDirectory = Join-Path $cacheRoot 'downloads'
    $versionsDirectory = Join-Path $cacheRoot 'versions'
    New-Item -ItemType Directory -Path $downloadsDirectory, $versionsDirectory -Force | Out-Null

    Write-Host 'Checking the public FACEIT AC download...'
    $response = Invoke-FaceitAcRequest -Url $ManifestUrl
    $manifestText = if ($response.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($response.Content) } else { [string]$response.Content }
    $manifest = $manifestText | ConvertFrom-Json
    Assert-FaceitAcReleaseSignature -Json $manifestText -Manifest $manifest
    $releaseVersion = $null
    if ($null -eq $manifest -or [string]$manifest.version -notmatch '\A[0-9]+(?:\.[0-9]+){1,3}\z' -or
        -not [Version]::TryParse([string]$manifest.version, [ref]$releaseVersion)) { throw 'The release manifest must contain a numeric version such as 1.0.' }
    $commit = [string]$manifest.commit
    if ($commit -notmatch '\A[0-9a-fA-F]{40}\z') { throw 'The release manifest contains an invalid commit.' }
    $commit = $commit.ToLowerInvariant()
    # The setup download and runtime update ZIP have separate integrity fields.
    # A partially specified installer must fail rather than silently falling
    # back to a different executable or bypassing the setup pages.
    $hasInstallerUrl = $null -ne $manifest.PSObject.Properties['installer_url']
    $hasInstallerHash = $null -ne $manifest.PSObject.Properties['installer_sha256']
    if ($hasInstallerUrl -or $hasInstallerHash) {
        if (-not ($hasInstallerUrl -and $hasInstallerHash) -or
            [string]$manifest.installer_sha256 -notmatch '\A[0-9a-fA-F]{64}\z') {
            throw 'The release manifest must provide installer_url and a valid installer_sha256 together.'
        }
        $packageUrl = Get-FaceitAcPackageUri -Value ([string]$manifest.installer_url) -InstallerOnly
        $packageHash = [string]$manifest.installer_sha256
    }
    else {
        $packageUrl = Get-FaceitAcPackageUri -Value ([string]$manifest.package_url)
        $packageHash = [string]$manifest.sha256
        if ($packageHash -notmatch '\A[0-9a-fA-F]{64}\z') { throw 'The release manifest contains an invalid SHA-256 checksum.' }
    }
    $packageHash = $packageHash.ToLowerInvariant()
    $installerPackage = $packageUrl.AbsolutePath.EndsWith('/FACEITInstaller_64.exe', [StringComparison]::Ordinal)
    $executablePackage = $installerPackage -or $packageUrl.AbsolutePath.EndsWith('/faceitclient.exe', [StringComparison]::Ordinal)
    $executableName = if ($installerPackage) { 'FACEITInstaller_64.exe' } else { 'faceitclient.exe' }
    $extension = if ($executablePackage) { '.exe' } else { '.zip' }
    if ($installerPackage) {
        $installerCache = Join-Path $downloadsDirectory ($commit + '.' + $packageHash.Substring(0, 12))
        New-Item -ItemType Directory -Path $installerCache -Force | Out-Null
        $packagePath = Join-Path $installerCache $executableName
    }
    else { $packagePath = Join-Path $downloadsDirectory ($commit + '.' + $packageHash.Substring(0, 12) + $extension) }
    if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash -ne $packageHash) {
        Write-Host ('Downloading version {0}...' -f [string]$manifest.version)
        Invoke-FaceitAcRequest -Url $packageUrl -Destination $packagePath
    }
    if ((Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash -ne $packageHash) {
        throw 'The download failed its SHA-256 check. The application was not started. Run the command again to retry.'
    }
    $cacheVersion = if ($installerPackage) { $commit + '.setup.' + $packageHash.Substring(0, 12) } else { $commit }
    $versionDirectory = Join-Path $versionsDirectory $cacheVersion
    $executable = Expand-FaceitAcPackage -PackagePath $packagePath -VersionDirectory $versionDirectory -ExecutablePackage:$executablePackage -ExecutableName $executableName
    Write-Host ('Downloaded version {0} ({1}).' -f [string]$manifest.version, $commit.Substring(0, 7))
    Write-Host "App: $executable"
    if ($NoRun) { Write-Host 'Download complete. The app was not started (-NoRun).'; return }
    if ($installerPackage) { Write-Host 'Opening setup. Review the pages and enter your key to install.' }
    else { Write-Host 'Opening activation. The app handles installation and shortcuts after the key is accepted.' }
    Start-Process -FilePath $executable -WorkingDirectory $versionDirectory
}

Invoke-FaceitAcInstall
