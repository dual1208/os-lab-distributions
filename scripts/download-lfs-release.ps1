#requires -Version 7.0
[CmdletBinding()]
param(
    [string] $Destination = (Join-Path $PSScriptRoot '..\out\oslab-release-staged')
)

$ErrorActionPreference = 'Stop'
$builderId = '587707242'
$builderName = 'osforge'
$outRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\out'))
$destinationRoot = [IO.Path]::GetFullPath($Destination)
$marker = Join-Path $outRoot 'lfs-download.exit'
$statusLog = Join-Path $outRoot 'lfs-download.log'
$exitCode = 1
$batchFiles = [Collections.Generic.List[string]]::new()
$maxParallel = 2

if (-not $destinationRoot.StartsWith(
        $outRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Destination must remain below the repository out directory.'
}

New-Item -ItemType Directory -Path $outRoot -Force | Out-Null
Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
"START=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))" |
    Set-Content -LiteralPath $statusLog -Encoding ascii

try {
    if (-not (Test-Path -LiteralPath $destinationRoot)) {
        New-Item -ItemType Directory -Path $destinationRoot | Out-Null
    }

    $inventoryText = & one-console machines list --provider digitalocean --output json
    if ($LASTEXITCODE -ne 0) { throw 'Inventory query failed.' }
    $inventory = $inventoryText | ConvertFrom-Json
    $builder = @($inventory.data | Where-Object {
        $_.id -eq $builderId -and $_.name -eq $builderName
    })
    if ($builder.Count -ne 1) { throw 'Exact builder is not uniquely present.' }
    $address = $builder[0].public_ipv4[0]

    $manifest = Join-Path $destinationRoot 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $manifest)) {
        $scpArguments = @(
            '-q', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
            "root@${address}:/srv/oslab-release/SHA256SUMS", "${destinationRoot}/"
        )
        & scp @scpArguments *> $null
        if ($LASTEXITCODE -ne 0) { throw 'Checksum-manifest transfer failed.' }
    }
    $entries = foreach ($line in Get-Content -LiteralPath $manifest) {
        if ($line -notmatch '^([0-9a-f]{64})  ([^/\\]+)$') {
            throw 'Malformed checksum manifest.'
        }
        [pscustomobject]@{ Hash = $Matches[1]; Name = $Matches[2] }
    }
    if (@($entries).Count -ne 13) { throw 'Unexpected checksum entry count.' }

    $pending = [Collections.Generic.Queue[object]]::new()
    foreach ($entry in $entries) {
        $path = Join-Path $destinationRoot $entry.Name
        if (Test-Path -LiteralPath $path) {
            $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -eq $entry.Hash) { continue }
        }
        $pending.Enqueue($entry)
    }

    $localDirectory = $destinationRoot.Replace('\', '/')
    while ($pending.Count -gt 0) {
        $wave = [Collections.Generic.List[object]]::new()
        while ($wave.Count -lt $maxParallel -and $pending.Count -gt 0) {
            $entry = $pending.Dequeue()
            $batchPath = Join-Path $outRoot ("sftp-$([guid]::NewGuid().ToString('N')).batch")
            @(
                "lcd `"$localDirectory`""
                "reget /srv/oslab-release/$($entry.Name) $($entry.Name)"
            ) | Set-Content -LiteralPath $batchPath -Encoding ascii
            [void] $batchFiles.Add($batchPath)
            $arguments = @(
                '-q', '-b', $batchPath, '-o', 'BatchMode=yes',
                '-o', 'ConnectTimeout=15', "root@$address"
            )
            $startParameters = @{
                FilePath = 'sftp.exe'
                ArgumentList = $arguments
                WindowStyle = 'Hidden'
                PassThru = $true
            }
            $process = Start-Process @startParameters
            [void] $wave.Add([pscustomobject]@{ Process = $process; Name = $entry.Name })
        }
        $waveFailed = $false
        foreach ($transfer in $wave) {
            $transfer.Process.WaitForExit()
            if ($transfer.Process.ExitCode -ne 0) {
                $waveFailed = $true
                "TRANSFER_FAILURE=$($transfer.Name):$($transfer.Process.ExitCode)" |
                    Add-Content -LiteralPath $statusLog -Encoding ascii
            }
        }
        if ($waveFailed) { throw 'Resume-capable artifact transfer failed.' }
    }

    if (@(Get-ChildItem -LiteralPath $destinationRoot -File).Count -ne 14) {
        throw 'Unexpected staged file count.'
    }
    foreach ($entry in $entries) {
        $path = Join-Path $destinationRoot $entry.Name
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $entry.Hash) { throw 'Downloaded checksum mismatch.' }
    }
    $exitCode = 0
} catch {
    'ERROR=download-or-checksum-validation-failed' |
        Add-Content -LiteralPath $statusLog -Encoding ascii
    $safeDetail = $_.Exception.Message -replace '([0-9]{1,3}\.){3}[0-9]{1,3}', '[redacted-address]'
    $safeDetail = $safeDetail -replace 'root@\S+', 'root@[redacted]'
    $safeDetail = $safeDetail -replace '[\r\n]+', ' '
    "ERROR_DETAIL=$safeDetail" | Add-Content -LiteralPath $statusLog -Encoding ascii
} finally {
    foreach ($batchPath in $batchFiles) {
        Remove-Item -LiteralPath $batchPath -Force -ErrorAction SilentlyContinue
    }
    @(
        "EXIT=$exitCode"
        "END=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    ) | Set-Content -LiteralPath $marker -Encoding ascii
}

exit $exitCode
