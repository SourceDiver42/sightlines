rule Sightlines_tlsh_b9e8a23f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b9e8a23f"
        date = "2026-11-07"
        campaign = "tlsh-b9e8a23f"
        family = ""
        hash = "08775ce48da0931f2ed7ba241325e8d151986d176bbe3943893f1df682f5e463"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b9e8a23f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s1 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s2 = "UPDATE \"%w\".sqlite_master SET sql = sqlite_add_constraint(sql, %.*Q, -1) WHERE type='table' AND tbl_" ascii
        $s3 = "SELECT sqlite_fail('constraint failed', %d) FROM %Q.%Q AS x WHERE x.%.*s IS NULL" ascii
        $s4 = "SELECT sqlite_fail('constraint %q already exists', %d) FROM \"%w\".sqlite_master WHERE type='table' AN" ascii
        $s5 = "SELECT sqlite_fail('constraint failed', %d) FROM %Q.%Q WHERE (%.*s) IS NOT TRUE" ascii
        $s6 = "UPDATE \"%w\".sqlite_master SET sql = sqlite_drop_constraint(sql, %s) WHERE type='table' AND tbl_name=" ascii
        $s7 = "UPDATE \"%w\".sqlite_master SET sql = sqlite_add_constraint(sqlite_drop_constraint(sql, %d), %.*Q, %d)" ascii
        $s8 = "D tbl_name=%Q COLLATE nocase AND sqlite_find_constraint(sql, %Q)" ascii
        $s9 = " WHERE type='table' AND tbl_name=%Q COLLATE nocase" ascii
        $s10 = ".?AV?$_Ref_count_obj2@U_Recursive_dir_enum_impl@filesystem@std@@@std@@" ascii
        $s11 = ".?AV?$_Ref_count_obj2@U_Dir_enum_impl@filesystem@std@@@std@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5624832 and 12 of them
}
