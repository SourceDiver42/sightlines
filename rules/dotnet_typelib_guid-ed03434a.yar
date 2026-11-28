rule Sightlines_dotnet_typelib_guid_ed03434a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-ed03434a"
        date = "2026-11-24"
        campaign = "dotnet_typelib_guid-ed03434a"
        family = ""
        hash = "1e73d374ea9fbde9c4b0d61dacfe70901d35fdc3184596846df4776ef74d2c7f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-ed03434a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Day {0}: [EOREUM GWE CHUNGDOL] Gang eoreum tteodol-myeo seonche/mul-lle tasigyeok! (-{1:F1}%)" wide
        $s1 = "Day {0}: [JEO-SU-WI JWACHO] Su-wi {1:F2}m Morae-teop geol-lim! Seonche chung-gyeok." wide
        $s2 = "Day {0}: [BUYU-MOK CHUNGDOL] Namu don-gi mul-lle tasi-pan tang-gyeok! (-{1:F1}%)" wide
        $s3 = "Day {0}: [GYERYU IDONG] Suro heung-ryu mat-chwo batjul {1:F1}m-ro idong." wide
        $s4 = "Day {0}: [HONGSU TWE-GAK] Su-wi {1:F2}m an-jeong-hwa. Suro gyeryu bok-gwi." wide
        $s5 = "[PYEONG-MYEON-DO] Suro Heureum, Batjul Gyeryu Wichi, Ssang-seonche (Keunbae / Tuszo)" wide
        $s6 = "Day {0}: [HONGSU GYEONGBO] Su-wi {1:F2}m geub-jeung! Bae-banga bu-gu-ro daepi gyeon-in." wide
        $s7 = "BAE-BANGA SEOLGYE MIT GYU-GYUK (Danube Mill Boat Specs)" wide
        $s8 = "Chuk To-keu (Torque): {0:F1} Nm (Wheel {1:F1} RPM @ 1.85m/s)" wide
        $s9 = "XSD Geomjeung: Yu-hyohan XML (Schema Validated OK)" wide
        $s10 = "Batjul Gyeryu Wichi Byeon-gyeong: {0} Hoesu (Hyun Wichi {1:F1} m)" wide
        $s11 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5105664 and 12 of them
}
