rule Sightlines_tlsh_794c795f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-794c795f"
        date = "2026-11-15"
        campaign = "tlsh-794c795f"
        family = "mirai"
        hash = "11500836558ff49dbd6e071894e053ac527996efb6de88e59c81015d54b1eed5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-794c795f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "azbd27sc1ycbgmz1dn2sf02c5tcow2lh" ascii
        $s1 = ",:HVVVVVVdt-0X+0X 0X-0x+0x 0x" ascii
        $s2 = "GCC: (GNU) 11.2.1 20211120" ascii
        $s3 = "GET /botstart HTTP/1.0" ascii
        $s4 = "LINUX_2.6.39" ascii
        $s5 = ".eh_frame_hdr" ascii
        $s6 = ".rela.dyn" ascii
        $s7 = ".gnu.hash" ascii
        $s8 = ".dynamic" ascii
        $s9 = ".comment" ascii
        $s10 = "Ct@9B|@9" ascii
        $s11 = "massload" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
