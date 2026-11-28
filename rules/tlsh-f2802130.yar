rule Sightlines_tlsh_f2802130_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f2802130"
        date = "2026-11-20"
        campaign = "tlsh-f2802130"
        family = ""
        hash = "24b278a8a0163363aa5df462a2a5662d6c182c28f1f086841469ecb23bf475b4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f2802130.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (MinGW-W64 x86_64-msvcrt-posix-seh, built by Brecht Sanders) 13.1.0" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "__deregister_frame_info" ascii
        $s3 = "__register_frame_info" ascii
        $s4 = "libgcc_s_dw2-1.dll" ascii
        $s5 = "Chrome Setup0" ascii
        $s6 = "gupdater2.dll" ascii
        $s7 = "260910173648Z" ascii
        $s8 = "310910174648Z0" ascii
        $s9 = "GupdaterStub" ascii
        $s10 = "@.eh_fram" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}
