rule Sightlines_tlsh_007939a5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-007939a5"
        date = "2026-11-10"
        campaign = "tlsh-007939a5"
        family = ""
        hash = "77d0122f32c68f059bba2257a58fb196ec72f6184c2445e5c0302cc504d01d6b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-007939a5.json"
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
        uint16(0) == 0x5A4D and filesize < 2622464 and 12 of them
}
