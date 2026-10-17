rule Sightlines_tlsh_85cfbe91_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-85cfbe91"
        date = "2026-10-17"
        campaign = "tlsh-85cfbe91"
        family = "mirai"
        hash = "448eefd781b3b6ecee0658169cf957924c985e578af5d94745f1c7460044c637"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-85cfbe91.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "Content-Type: application/json" ascii
        $s5 = "GET /api/v1/status HTTP/1.1" ascii
        $s6 = "/bin/busybox wget http://" ascii
        $s7 = "POST /api/sync HTTP/1.1" ascii
        $s8 = "/bin/busybox echo -ne " ascii
        $s9 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Host: api.svc.local" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
