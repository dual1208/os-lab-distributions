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
    if (Test-Path -LiteralPath $destinationRoot) {
        if (Get-ChildItem -LiteralPath $destinationRoot -Force) {
            throw 'Destination is not empty.'
        }
    } else {
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

    $scpArguments = @(
        '-q', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
        "root@${address}:/srv/oslab-release/*", "${destinationRoot}/"
    )
    & scp @scpArguments *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Artifact transfer failed.' }

    $manifest = Join-Path $destinationRoot 'SHA256SUMS'
    $entries = foreach ($line in Get-Content -LiteralPath $manifest) {
        if ($line -notmatch '^([0-9a-f]{64})  ([^/\\]+)$') {
            throw 'Malformed checksum manifest.'
        }
        [pscustomobject]@{ Hash = $Matches[1]; Name = $Matches[2] }
    }
    if (@($entries).Count -ne 13) { throw 'Unexpected checksum entry count.' }
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
} finally {
    @(
        "EXIT=$exitCode"
        "END=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    ) | Set-Content -LiteralPath $marker -Encoding ascii
}

exit $exitCode
