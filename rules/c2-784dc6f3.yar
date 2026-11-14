rule Sightlines_c2_784dc6f3_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-784dc6f3"
        date = "2026-11-03"
        campaign = "c2-784dc6f3"
        family = "mirai"
        hash = "03076bface763d824f6cecf71187c3ce7193470cc7215cdfe7c8547eaf7e4e80"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-784dc6f3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "for c in systemd-update kworker/0:1-eve jbd2/sda1-8 rcu_preempt migration/1 ksoftirqd/0 kcompactd0 w" ascii
        $s1 = "Hjjly}3)}lq}&a}de%hyye`jh}`fg&qa}de\"qde%hyye`jh}`fg&qde2x49'0%`dhnl&~lky%#&#2x49'1" ascii
        $s2 = "Jfg}lg}$]pyl3)hyye`jh}`fg&q$~~~$of{d$|{elgjfmlm" ascii
        $s3 = "nohup \"$BIN\" lover.ss >/dev/null 2>&1 &" ascii
        $s4 = "# Short-Description: System Update Service" ascii
        $s5 = "/etc/systemd/system/multi-user.target.wants/systemd-update.service" ascii
        $s6 = "/lib/systemd/system/systemd-update.service" ascii
        $s7 = "/etc/systemd/system/systemd-update.service" ascii
        $s8 = "Description=System Update Service" ascii
        $s9 = "Hjjly}$Ehgn|hnl3)lg$\\Z%lg2x49'1" ascii
        $s10 = "3<9'9 )Nljbf&;9899898)O`{lofq&<9'9" ascii
        $s11 = "/etc/profile.d/systemd-update.sh" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
