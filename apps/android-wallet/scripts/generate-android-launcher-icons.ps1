param()

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$walletRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $walletRoot 'app/src-tauri/icons/icon.png'
$resRoot = Join-Path $walletRoot 'app/src-tauri/gen/android/app/src/main/res'
$sizes = [ordered]@{
    'mipmap-mdpi' = 108
    'mipmap-hdpi' = 162
    'mipmap-xhdpi' = 216
    'mipmap-xxhdpi' = 324
    'mipmap-xxxhdpi' = 432
}

$source = [System.Drawing.Bitmap]::FromFile($sourcePath)
try {
    $minX = $source.Width
    $minY = $source.Height
    $maxX = -1
    $maxY = -1
    for ($y = 0; $y -lt $source.Height; $y++) {
        for ($x = 0; $x -lt $source.Width; $x++) {
            if ($source.GetPixel($x, $y).A -le 8) { continue }
            $minX = [Math]::Min($minX, $x)
            $minY = [Math]::Min($minY, $y)
            $maxX = [Math]::Max($maxX, $x)
            $maxY = [Math]::Max($maxY, $y)
        }
    }
    if ($maxX -lt 0) { throw 'The source CF mark has no visible pixels.' }

    $centerX = ($minX + $maxX) / 2.0
    $centerY = ($minY + $maxY) / 2.0
    $maxRadius = 0.0
    for ($y = $minY; $y -le $maxY; $y++) {
        for ($x = $minX; $x -le $maxX; $x++) {
            if ($source.GetPixel($x, $y).A -le 8) { continue }
            $radius = [Math]::Sqrt([Math]::Pow($x - $centerX, 2) + [Math]::Pow($y - $centerY, 2))
            $maxRadius = [Math]::Max($maxRadius, $radius)
        }
    }

    # Android's 108 dp adaptive foreground has a centered 66 dp safe circle.
    # Keep the entire textured mark 10% inside that circle for OEM masks.
    foreach ($density in $sizes.Keys) {
        $size = $sizes[$density]
        $safeRadius = $size * 33.0 / 108.0
        $scale = ($safeRadius * 0.9) / $maxRadius
        $target = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($target)
            try {
                $graphics.Clear([System.Drawing.Color]::Transparent)
                $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
                $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
                $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $destination = [System.Drawing.RectangleF]::new(
                    ([single]($size / 2.0 - $centerX * $scale)),
                    ([single]($size / 2.0 - $centerY * $scale)),
                    ([single]($source.Width * $scale)),
                    ([single]($source.Height * $scale))
                )
                $graphics.DrawImage($source, $destination)
            } finally {
                $graphics.Dispose()
            }
            $outputPath = Join-Path (Join-Path $resRoot $density) 'ic_launcher_foreground.png'
            $target.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
            Write-Output "$density foreground: ${size}x${size}, mark radius $([Math]::Round($safeRadius * 0.9, 1)) px"
        } finally {
            $target.Dispose()
        }
    }
} finally {
    $source.Dispose()
}
