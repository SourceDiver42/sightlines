rule Sightlines_c2_08eb57ca_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-08eb57ca"
        date = "2026-11-22"
        campaign = "c2-08eb57ca"
        family = "mirai"
        hash = "2c9793b75224c41b67da0047be4bfc3636c5be86e9de5f9388ab5f762b21543c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-08eb57ca.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Set-Cookie: NID=207=QioO2ZqRsR6k1wtvXjuuhLrXYtl6ki8SQhf56doo_wcADvldNoHfnKvFk1YXdxSVTWnmqHQVPC6ZudGn" ascii
        $s1 = "eMs7vDftJ6vB36B0OCDy_KetZ3sOT_ZAHcmi1pAGeO0VekZ0SYt_UXMjcDhuvNVW7hbuHEeXQFSgBywyzB6mF2EVN00; expires" ascii
        $s2 = "Set-Cookie: 1P_JAR=2021-01-13-18; expires=Fri, 12-Feb-2021 18:18:25 GMT; path=/; domain=.google.com;" ascii
        $s3 = "v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE AES-CBC key=128bits SHA PSK  " ascii
        $s4 = "v1.0 xchg=id-prot [KEY-XCHG] [NONCE]  {CISCO-UNITY}  {RFC3706-DPD}   {XAUTH} [NAT-D] [NAT-D]" ascii
        $s5 = "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877" ascii
        $s6 = "v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE 3DES-CBC SHA PSK" ascii
        $s7 = "=Thu, 15-Jul-2021 18:18:25 GMT; path=/; domain=.google.com; HttpOnly" ascii
        $s8 = "match ftp m/^220.*Welcome to .*Pure-?FTPd (\\d\\S+\\s*)/ p/Pure-FTPd/ v/$1/ cpe:/a:pureftpd:pure-ftpd:$" ascii
        $s9 = "match printer m|^([\\w-_.]+): lpd: Illegal service request\\n$| p/lpd/ h/$1/" ascii
        $s10 = "SEE (https://github.com/robertdavidgraham/masscan) FOR MORE HELP" ascii
        $s11 = "From: Alice <sip:alice@atlanta.com>;tag=1928301774" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 5399568 and 12 of them
}
