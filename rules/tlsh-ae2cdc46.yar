rule Sightlines_tlsh_ae2cdc46_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ae2cdc46"
        date = "2026-10-24"
        campaign = "tlsh-ae2cdc46"
        family = "mirai"
        hash = "01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ae2cdc46.json"
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
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Unknown error Success" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}
