rule Sightlines_tlsh_d42af701_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d42af701"
        date = "2026-11-24"
        campaign = "tlsh-d42af701"
        family = "remcos"
        hash = "47b6cd26a1cd791cbc9607abac4ec9e97d752ff55c17310062685cee4301953a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d42af701.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1weQ4NaWA0NWoUBlB0JxUYFD4MVjcwPh1zVQkFJi8ADjYNOTMHC3QpASoQHCEMBA0MPGNuEScMDmw3BTZvNgFoVioJHRg+DCMNLQ" ascii
        $s1 = "RwZwkNaV0xDmp8aW1weQ4NaWA0MGoRAWhJFBoGCC0MVzMjOxJ3CRQXZzIDCiUVDDcTQFpyLCg7MBspOAIIKVoKEQ4dMAsuBwwMaB" ascii
        $s2 = "cDaBQ3fWgvKhcaGD43Nm9qH25dOSEGC2wWDSMOCQB8TQ0qC2sQHl1TAAIMXl0HKDIQHBc0NQwYFmtvDhQMDAg+ByYiMiRuDHAaBj" ascii
        $s3 = "dsfCcQDRgyCzwrIzh2c3sZcwwpO2tRMDk3E1RjGAoyOzQXCCULNS5rYQo5PGoTGz1SCConCwwRIzMPNAM8KzY4KHdVCQRuPhNoKl" ascii
        $s4 = "ASQUkiLQs+EhEuUDg0F0lbFxUuFjAbJy8wCyJ1bXQnDwwPDSg0FBkUQAARE24XDRcdIC4KLHtxFy0yLhAaVEoTHAtTWi0sKT0cEx" ascii
        $s5 = "FpECcJLTkobE0aBwgzO2tVFjk3E0NaOSsQGjAUXTEOanxpbXB5Dg1pYDQ1amMVbQl5EAppYAkwUWMKEQkAEBRuYAkNVFgKDnUAaR" ascii
        $s6 = "        PAYLOAD: \"HQg2DjEOanxpbXB5Dg1pYDQ1amMVbQl5EAppYAkwUWMKEQkAEBRuYAkNVFgKDnUAaRRwZwkNaV0xDmp8aW" ascii
        $s7 = "    // Entry point (identical exit semantics)" ascii
    condition:
        filesize < 2065840 and 8 of them
}
