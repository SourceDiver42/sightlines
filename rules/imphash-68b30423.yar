rule Sightlines_imphash_68b30423_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-68b30423"
        date = "2026-11-15"
        campaign = "imphash-68b30423"
        family = ""
        hash = "24d68ca16b05915a71325fa339216f7342e4731fb069f979bb5390a6c4cf3450"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-68b30423.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "j2d_mlib_ImageConvKernelConvert" ascii
        $s1 = "j2d_mlib_ImageCreateStruct" ascii
        $s2 = "OpenJDK Platform binary" wide
        $s3 = "http://www.eclipse.org/0" ascii
        $s4 = "j2d_mlib_ImageConvMxN" ascii
        $s5 = "\\$ UVWATAUAVAWHcYHLcaLL" ascii
        $s6 = "j2d_mlib_ImageLookUp" ascii
        $s7 = "j2d_mlib_ImageAffine" ascii
        $s8 = "j2d_mlib_ImageDelete" ascii
        $s9 = "Eclipse Adoptium" wide
        $s10 = "380114235959Z0i1" ascii
        $s11 = "360903235959Z0c1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
