rule Sightlines_tlsh_f93e9dd6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f93e9dd6"
        date = "2026-11-19"
        campaign = "tlsh-f93e9dd6"
        family = ""
        hash = "20370532a621f2611b51ad0369fb1f48c5208f49a971b56b44f1e2d321c41cb0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f93e9dd6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Hyeonjae Banjirum (Bell Radius): {0:F2} ft (Limit: {1:F1} ft)" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "Hyeonjae Banjirum (Bell Radius): 3.0 ft (Lim 18)" wide
        $s3 = "Cheon-mak hwangi-ro gongki-reul sunhwan-sikyeoss-seumnida. Oyeomdo: {0:F1}%" wide
        $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "[Ilji Sijak] Bell Pit chaegul chang rod-wallyo. Jogeop ilsoo: {0} il." wide
        $s6 = "Haru jinhaeng: Jogeop {0} il-cha, ilgan chaegul: {1:F2} ton, cheongjang: {2:F1}%." wide
        $s7 = "Mool Yooip-ryang (Water Inflow Rate) [gal/d]:" wide
        $s8 = "Sangse: Chong chae-gul {0:F1} ton jung {1:F1} ton chulha. Gwang-gool cheongjang eungryeok: {2:F1}%." wide
        $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s10 = "Banjirum Gyeonje (Bell Radius Limit) [ft]:" wide
        $s11 = "Bagoni-wa yangsoogi-ro mool-eul ppeonaess-seumnida. Hyeonjae soowi: {0:F1} ft" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1649664 and 12 of them
}
