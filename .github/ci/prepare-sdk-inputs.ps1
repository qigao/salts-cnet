param([switch]$Resolve)

$ErrorActionPreference = 'Stop'
$root = 'build/ci-inputs'
$reader = 'build/ci-infrastructure/vcpkg-cache/scripts/restore-native-dependency.py'
$matrix = Get-Content .github/ci/sdk-matrix.json -Raw | ConvertFrom-Json

if ($Resolve) {
  New-Item -ItemType Directory -Path $root -Force | Out-Null
  $reply = & gh api repos/qigao/salts-base/releases/latest
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  $release = $reply | ConvertFrom-Json
  $stable = $release.tag_name -match '^v(\d+\.\d+\.\d+)$'
  if ($release.draft -or $release.prerelease -or -not $stable) {
    throw 'A stable SaltsBase semantic-version release is required'
  }
  $version = $Matches[1]
  $manifest = @($release.assets | Where-Object name -eq "salts-base-$version-manifest.json")
  if ($manifest.Count -ne 1 -or $manifest[0].digest -cnotmatch '^sha256:([0-9a-f]{64})$') {
    throw 'The SaltsBase release must provide one SHA-256-qualified manifest'
  }
  $manifestHash = $Matches[1]
  @{version=$version; tag=$release.tag_name; manifest=$manifest[0]; assets=$release.assets} |
    ConvertTo-Json -Depth 12 | Set-Content "$root/salts-base-release.json" -Encoding utf8
  "matrix=$($matrix | ConvertTo-Json -Depth 8 -Compress)" >> $env:GITHUB_OUTPUT
  "manifest_sha256=$manifestHash" >> $env:GITHUB_OUTPUT
  return
}

New-Item -ItemType Directory -Path "$root/locks" -Force | Out-Null
$release = Get-Content "$root/salts-base-release.json" -Raw | ConvertFrom-Json

function Get-LockedArchive([string]$Name, [string]$Url, [string]$Hash) {
  $lock = "$root/locks/$Name.lock.json"
  @{schema=1; source=@{kind='url'; url=$Url}; sha256=$Hash} |
    ConvertTo-Json -Depth 4 | Set-Content $lock -Encoding utf8
  & python $reader download $lock --destination "$root/blobs"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Get-ReleaseAsset($Asset) {
  $hash = $Asset.digest.Substring('sha256:'.Length)
  & python .github/ci/download-release-asset.py $Asset.browser_download_url `
    $hash $Asset.size "$root/blobs"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

# These are the release API's canonical public asset URLs, not a second source
# attempted after failure. Every blob is addressed and verified by SHA-256.
$manifestHash = $release.manifest.digest.Substring('sha256:'.Length)
Get-ReleaseAsset $release.manifest
Copy-Item -LiteralPath "$root/blobs/$manifestHash" -Destination "$root/salts-base-manifest.json"
$manifest = Get-Content "$root/salts-base-manifest.json" -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or $manifest.name -cne 'SaltsBase' -or
    $manifest.repository -cne 'https://github.com/qigao/salts-base' -or
    $manifest.version -cne $release.version -or $manifest.tag -cne $release.tag -or
    $manifest.ci.conclusion -cne 'success') {
  throw 'Invalid or unqualified SaltsBase release manifest'
}

foreach ($profile in ($matrix.include.sdk | Sort-Object -Unique)) {
  $sdk = @($manifest.sdks | Where-Object platform -eq $profile)
  if ($sdk.Count -ne 1) { throw "SaltsBase $($release.version) has no SDK for $profile" }
  $sdk = $sdk[0]
  if ($sdk.file -cne "salts-base-$($release.version)-$profile.tar") {
    throw 'Unexpected SaltsBase archive name'
  }
  $asset = @($release.assets | Where-Object name -eq $sdk.file)
  if ($asset.Count -ne 1 -or $asset[0].digest -cne "sha256:$($sdk.sha256)" -or
      $asset[0].size -ne $sdk.sizeBytes) {
    throw "SaltsBase manifest does not match release asset $($sdk.file)"
  }
  Get-ReleaseAsset $asset[0]
  if ((Get-Item -LiteralPath "$root/blobs/$($sdk.sha256)").Length -ne $sdk.sizeBytes) {
    throw "SaltsBase archive size mismatch: $($sdk.file)"
  }
}

foreach ($triplet in ($matrix.include.triplet | Sort-Object -Unique)) {
  & python $reader download "cmake/dependencies/$triplet.lock.json" --destination "$root/blobs"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$contract = Get-Content build/ci-infrastructure/vcpkg-cache/compiler-contracts/release-obfuscation.json -Raw | ConvertFrom-Json
$compiler = $contract.sources.'llvm-mingw'
$asset = @($compiler.assets | Where-Object host -eq 'windows-x64')
if ($asset.Count -ne 1) { throw 'One locked Windows x64 LLVM-MinGW compiler is required' }
$url = "https://github.com/$($compiler.repository)/releases/download/$($compiler.release_tag)/$($asset[0].name)"
Get-LockedArchive 'windows-compiler' $url $asset[0].sha256
"SaltsBase $($release.version): $($manifest.commit); producer CI $($manifest.ci.runId). Native SDK inputs prepared once for this run." >> $env:GITHUB_STEP_SUMMARY
