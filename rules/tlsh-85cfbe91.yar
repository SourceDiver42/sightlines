rule Sightlines_tlsh_85cfbe91_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-85cfbe91"
        date = "2026-10-24"
        campaign = "tlsh-85cfbe91"
        family = "mirai"
        hash = "0e1bef0a80af04a033f0e9f29b9b97475b65503ec559af5826fe2af45edba7e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-85cfbe91.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "Content-Type: application/json" ascii
        $s5 = "/bin/busybox hostname PBOC" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s11 = "/bin/busybox echo > " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}
