rule Sightlines_tlsh_616b3b91_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-616b3b91"
        date = "2026-11-02"
        campaign = "tlsh-616b3b91"
        family = "rustystealer"
        hash = "50fdd8477244d8b3a59aa81bb2020ad2aad38d557039b36a38f6a8a74f87a969"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-616b3b91.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RUST_LIB_BACKTRACERUST_BACKTRACE\\.lock count overflow in reentrant mutex/rustc/8bab26f4f68e0e26f0bb7" ascii
        $s1 = "Test-Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender'){$source='Group Policy'};" ascii
        $s2 = "uded.valueINSERT INTO configuration(key,value) VALUES('device_name',?) ON CONFLICT(key) DO UPDATE SE" ascii
        $s3 = "INSERT INTO configuration(key,value) VALUES('device_id',?) ON CONFLICT(key) DO UPDATE SET value=excl" ascii
        $s4 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s5 = "UTERNAME${global_app_data}PROGRAMDATA${program_files}PROGRAMFILES${windows}${client_name}CLIENTNAME$" ascii
        $s6 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s7 = "SELECT value FROM configuration WHERE key=?INSERT INTO configuration(key,value) VALUES(?,?) ON CONFL" ascii
        $s8 = "SELECT idx,count(*) FROM %Q.sqlite_stat4 GROUP BY idx COLLATE nocase" ascii
        $s9 = "if(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Defender'){$source='MDM'}elseif(" ascii
        $s10 = "RUST_MIN_STACKC:\\Users\\Admin\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\tokio-1.53.1\\src\\r" ascii
        $s11 = "$onboard=(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17096750 and 11 of them
}
