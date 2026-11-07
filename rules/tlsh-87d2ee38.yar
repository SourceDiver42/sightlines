rule Sightlines_tlsh_87d2ee38_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-87d2ee38"
        date = "2026-11-04"
        campaign = "tlsh-87d2ee38"
        family = "mirai"
        hash = "3ac52a382fa7402bdd19c1531bb6801c9a338fb9797087934539eed6b3feafe8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-87d2ee38.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=" ascii
        $s1 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336" ascii
        $s2 = "e=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:servi" ascii
        $s3 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyl" ascii
        $s4 = "Hjjly}3)}lq}&a}de%hyye`jh}`fg&qa}de\"qde%hyye`jh}`fg&qde2x49'0%`dhnl&~lky%#&#2x49'1" ascii
        $s5 = "Jfg}lg}$]pyl3)hyye`jh}`fg&q$~~~$of{d$|{elgjfmlm" ascii
        $s6 = "\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\"" ascii
        $s7 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" ascii
        $s8 = "Hjjly}$Ehgn|hnl3)lg$\\Z%lg2x49'1" ascii
        $s9 = "3<9'9 )Nljbf&;9899898)O`{lofq&<9'9" ascii
        $s10 = "hkjmlona`cbedgfyx{z}|" ascii
        $s11 = "Connection: keep-alive" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
