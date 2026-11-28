rule Sightlines_rich_header_hash_0c813dde_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-0c813dde"
        date = "2026-11-11"
        campaign = "rich_header_hash-0c813dde"
        family = ""
        hash = "06c424b6c51b499beaf8d1fb0f3253f748aafa88695cc8774061626614104932"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-0c813dde.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "</h4><div class=\"row\" style=\"margin-top:14px;font-weight:900;font-size:12px;color:var(--mut)\">ID " ascii
        $s1 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s2 = "stify-content:center;background:rgba(139,92,246,.2);border:1px solid rgba(167,139,250,.5);box-shadow" ascii
        $s3 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s4 = ".circ{width:44px;height:44px;border-radius:50%;background:linear-gradient(135deg,#a78bfa,#6d28d9);fl" ascii
        $s5 = ".tag{font-size:10px;font-weight:900;color:var(--amber);background:rgba(251,191,36,.15);border:1px so" ascii
        $s6 = "UPDATE \"%w\".sqlite_master SET sql = sqlite_add_constraint(sql, %.*Q, -1) WHERE type='table' AND tbl_" ascii
        $s7 = ".tool{width:132px;height:132px;filter:drop-shadow(0 14px 22px rgba(109,40,217,.6));animation:fl 4s e" ascii
        $s8 = "und:linear-gradient(180deg,#a78bfa,#7c3aed);box-shadow:0 8px 24px rgba(124,58,237,.4),inset 0 1px 0 " ascii
        $s9 = "SELECT sqlite_fail('constraint failed', %d) FROM %Q.%Q AS x WHERE x.%.*s IS NULL" ascii
        $s10 = ".per button.on{border-color:var(--v2);background:rgba(139,92,246,.28);box-shadow:0 0 18px rgba(139,9" ascii
        $s11 = ".btn{display:block;margin:26px auto 0;width:min(100%,460px);padding:15px;border:0;border-radius:999p" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3940352 and 12 of them
}
