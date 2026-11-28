rule Sightlines_c2_b976ac40_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-b976ac40"
        date = "2026-11-06"
        campaign = "c2-b976ac40"
        family = "mirai"
        hash = "12029b1db51d389f109b6e78d4e666ee06d9332e9c9e80d942dc09f34ad71cb6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-b976ac40.json"
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
