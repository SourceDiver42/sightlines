rule Sightlines_tlsh_0609aa68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0609aa68"
        date = "2026-11-15"
        campaign = "tlsh-0609aa68"
        family = ""
        hash = "0487aa0075b899338d22253d93457f666e7a871e65ac81183052b461f29205bd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0609aa68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\Software\\Classes\\" wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide
        $s2 = "nihanaxagofasete" wide
        $s3 = "V9e-!~3NY!Xur" ascii
        $s4 = "DA=k3rw-$Q>C" ascii
        $s5 = "\\REGISTRY\\USER" wide
        $s6 = "Update Status" ascii
        $s7 = ";Abr9-b>7c54" ascii
        $s8 = "f;TEOq;X+2Wh" ascii
        $s9 = "f88iibCAZ\\jk" ascii
        $s10 = "Title Status" ascii
        $s11 = "18sAl)pV-[U" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 19009536 and 12 of them
}
