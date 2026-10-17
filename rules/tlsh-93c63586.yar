rule Sightlines_tlsh_93c63586_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-93c63586"
        date = "2026-10-17"
        campaign = "tlsh-93c63586"
        family = "mirai"
        hash = "05fc0e8dc8e4f37ea41415c40052d36b941d2f3a42e59b0b42420089e17107ed"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-93c63586.json"
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
        $s9 = "/bin/busybox echo > " ascii
        $s10 = "Host: api.svc.local" ascii
        $s11 = "KERN_SECURELEVEL" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
