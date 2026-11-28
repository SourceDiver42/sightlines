rule Sightlines_imphash_53f65dcb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-53f65dcb"
        date = "2026-11-15"
        campaign = "imphash-53f65dcb"
        family = ""
        hash = "0702917a944d3b779881b3c5da4cf50a6c94903a60883eac868696723e551221"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-53f65dcb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "OpenJDK Platform binary" wide
        $s1 = "__stdio_common_vfwprintf_s" ascii
        $s2 = "__stdio_common_vswprintf_s" ascii
        $s3 = "http://www.eclipse.org/0" ascii
        $s4 = "__stdio_common_vfprintf_s" ascii
        $s5 = "__stdio_common_vfwscanf" ascii
        $s6 = "__stdio_common_vswscanf" ascii
        $s7 = "__stdio_common_vfscanf" ascii
        $s8 = "Eclipse Adoptium" wide
        $s9 = "380114235959Z0i1" ascii
        $s10 = "360903235959Z0c1" ascii
        $s11 = "Full Version" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
