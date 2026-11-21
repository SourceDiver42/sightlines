rule Sightlines_tlsh_369125e9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-369125e9"
        date = "2026-11-04"
        campaign = "tlsh-369125e9"
        family = ""
        hash = "19fbe95cccbd236b2454cdc0116180fbc7f509e9c08e0b90cbcb29d02912761c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-369125e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " helper thread complete[DEBUG:MAIN] Waiting for TRANSMISSION #1 (T=90s)...[DEBUG:MAIN] " ascii
        $s1 = " FAST thread panicked[DEBUG:MAIN] Waiting for TRANSMISSION #2 (T=300s)...[DEBUG:MAIN] " ascii
        $s2 = "RUST_LIB_BACKTRACERUST_BACKTRACE\\.lock count overflow in reentrant mutex/rustc/8bab26f4f68e0e26f0bb7" ascii
        $s3 = "Test-Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender'){$source='Group Policy'};" ascii
        $s4 = "uded.valueINSERT INTO configuration(key,value) VALUES('device_name',?) ON CONFLICT(key) DO UPDATE SE" ascii
        $s5 = "RUST_BACKTRACE\\lock count overflow in reentrant mutex/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea452" ascii
        $s6 = "INSERT INTO configuration(key,value) VALUES('device_id',?) ON CONFLICT(key) DO UPDATE SET value=excl" ascii
        $s7 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s8 = "BRIDGE_BACKSTAGE_OPERA_UIA_CLICK@backstage.input.opera_uia stage=control_walker result=failed hr=" ascii
        $s9 = "UTERNAME${global_app_data}PROGRAMDATA${program_files}PROGRAMFILES${windows}${client_name}CLIENTNAME$" ascii
        $s10 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s11 = "OMPLETE (T=300s) running in parallel...[DEBUG:MAIN] Waiting for collectors...[DEBUG:MAIN] " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 22084652 and 10 of them
}
