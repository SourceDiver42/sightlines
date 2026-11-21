rule Sightlines_tlsh_b0229732_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b0229732"
        date = "2026-11-18"
        campaign = "tlsh-b0229732"
        family = "mirai"
        hash = "2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b0229732.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "clang version 18.1.6 (https://github.com/ziglang/zig-bootstrap 98bc6bf4fc4009888d33941daf6b600d20a42" ascii
        $s1 = "Hjjly}3)}lq}&a}de%hyye`jh}`fg&qa}de\"qde%hyye`jh}`fg&qde2x49'0%`dhnl&~lky%#&#2x49'1" ascii
        $s2 = "Jfg}lg}$]pyl3)hyye`jh}`fg&q$~~~$of{d$|{elgjfmlm" ascii
        $s3 = "systemctl enable %s.service 2>/dev/null" ascii
        $s4 = "    echo \"Usage: $0 {start|stop|restart}\"" ascii
        $s5 = "/usr/lib/accountsservice/accounts-daemon" ascii
        $s6 = "systemctl start %s.service 2>/dev/null" ascii
        $s7 = "REGISTER linux %s %d %ld %ld full %.0f %s" ascii
        $s8 = "update-rc.d %s defaults 2>/dev/null" ascii
        $s9 = "Description=System Update Service" ascii
        $s10 = "Hjjly}$Ehgn|hnl3)lg$\\Z%lg2x49'1" ascii
        $s11 = "3<9'9 )Nljbf&;9899898)O`{lofq&<9'9" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
