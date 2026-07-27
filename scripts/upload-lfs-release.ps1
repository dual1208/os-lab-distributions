#requires -Version 7.0
[CmdletBinding()]
param(
    [string] $Repository = 'dual1208/os-lab-distributions',
    [string] $Tag = 'oslab-2026.07'
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outRoot = Join-Path $repoRoot 'out'
$payloadRoot = Join-Path $outRoot 'oslab-release-staged'
$downloadMarker = Join-Path $outRoot 'lfs-download.exit'
$exitMarker = Join-Path $outRoot 'lfs-upload.exit'
$statusLog = Join-Path $outRoot 'lfs-upload.log'
$exitCode = 1
$expectedNames = @(
    'BUILD-MANIFEST.txt'
    'LFS-SOURCE-SHA256SUMS'
    'REASSEMBLE.md'
    'ROOTFS-SHA256SUMS'
    'SHA256SUMS'
    'SOURCE-SHA256SUMS'
    'UPSTREAMS.tsv'
    'initramfs-7.1.5-oslab.img'
    'kernel-7.1.5-oslab.config'
    'oslab-2026.07-skylake-rootfs.tar.zst.part00'
    'oslab-2026.07-skylake-rootfs.tar.zst.part01'
    'oslab-2026.07-zen5-rootfs.tar.zst.part00'
    'oslab-2026.07-zen5-rootfs.tar.zst.part01'
    'vmlinuz-7.1.5-oslab'
)

function Get-DraftRelease {
    $text = & gh api "repos/$Repository/releases?per_page=100"
    if ($LASTEXITCODE -ne 0) { throw 'GitHub release lookup failed.' }
    $matches = @(($text | ConvertFrom-Json) | Where-Object tag_name -eq $Tag)
    if ($matches.Count -ne 1) { throw 'Exact GitHub release is not unique.' }
    $release = $matches[0]
    if (-not $release.draft -or -not $release.prerelease -or $release.tag_name -ne $Tag) {
        throw 'Target is not the exact draft prerelease.'
    }
    return $release
}

Remove-Item -LiteralPath $exitMarker -Force -ErrorAction SilentlyContinue
"START=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))" |
    Set-Content -LiteralPath $statusLog -Encoding ascii

try {
    if (-not (Select-String -LiteralPath $downloadMarker -Pattern '^EXIT=0$' -Quiet)) {
        throw 'Local download gate is not successful.'
    }
    $actualNames = @(Get-ChildItem -LiteralPath $payloadRoot -File |
        Sort-Object Name | ForEach-Object Name)
    if (Compare-Object $expectedNames $actualNames) {
        throw 'Local release payload is not the exact expected file set.'
    }

    $localHashes = @{}
    foreach ($name in $expectedNames) {
        $path = Join-Path $payloadRoot $name
        $localHashes[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $release = Get-DraftRelease
    foreach ($name in $expectedNames) {
        $path = Join-Path $payloadRoot $name
        $asset = @($release.assets | Where-Object name -eq $name)
        $wantedDigest = "sha256:$($localHashes[$name])"
        if ($asset.Count -eq 1 -and $asset[0].digest -eq $wantedDigest) {
            "SKIP=$name" | Add-Content -LiteralPath $statusLog -Encoding ascii
            continue
        }
        $arguments = @('release', 'upload', $Tag, $path, '--repo', $Repository)
        if ($asset.Count -gt 0) { $arguments += '--clobber' }
        & gh @arguments >> $statusLog 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Asset upload failed: $name" }
        "UPLOADED=$name" | Add-Content -LiteralPath $statusLog -Encoding ascii
        $release = Get-DraftRelease
        $uploaded = @($release.assets | Where-Object name -eq $name)
        if ($uploaded.Count -ne 1 -or $uploaded[0].digest -ne $wantedDigest) {
            throw "Uploaded asset digest mismatch: $name"
        }
    }

    $release = Get-DraftRelease
    if (@($release.assets).Count -ne $expectedNames.Count) {
        throw 'Draft release has an unexpected asset count.'
    }
    foreach ($name in $expectedNames) {
        $asset = @($release.assets | Where-Object name -eq $name)
        if ($asset.Count -ne 1 -or
            $asset[0].digest -ne "sha256:$($localHashes[$name])") {
            throw "Final release asset mismatch: $name"
        }
    }
    $exitCode = 0
} catch {
    'ERROR=release-upload-or-digest-validation-failed' |
        Add-Content -LiteralPath $statusLog -Encoding ascii
    $safeDetail = $_.Exception.Message -replace '[\r\n]+', ' '
    "ERROR_DETAIL=$safeDetail" | Add-Content -LiteralPath $statusLog -Encoding ascii
} finally {
    @(
        "EXIT=$exitCode"
        "END=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    ) | Set-Content -LiteralPath $exitMarker -Encoding ascii
}

exit $exitCode
