rule Sightlines_signer_cert_sha1_b5077fa2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-b5077fa2"
        date = "2026-11-10"
        campaign = "signer_cert_sha1-b5077fa2"
        family = ""
        hash = "1a2c63bd056fb7c5137b652fdf9d1e0b53af7f457e5ff545ee38bab6673afe50"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-b5077fa2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (MinGW-W64 x86_64-msvcrt-posix-seh, built by Brecht Sanders) 13.1.0" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "__deregister_frame_info" ascii
        $s3 = "__register_frame_info" ascii
        $s4 = "libgcc_s_dw2-1.dll" ascii
        $s5 = "Chrome Setup0" ascii
        $s6 = "260910173648Z" ascii
        $s7 = "310910174648Z0" ascii
        $s8 = "@.eh_fram" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11316464 and 9 of them
}
