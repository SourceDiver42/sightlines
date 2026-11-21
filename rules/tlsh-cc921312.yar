rule Sightlines_tlsh_cc921312_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cc921312"
        date = "2026-11-15"
        campaign = "tlsh-cc921312"
        family = "mirai"
        hash = "158efa1360dc715804e3142da684f3bc8a6cd07e84d0f3377c058a18eb029d6f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cc921312.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".gnu.attributes" ascii
        $s1 = ".MIPS.abiflags" ascii
        $s2 = ".reginfo" ascii
        $s3 = ".comment" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 4 of them
}
