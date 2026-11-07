rule Sightlines_tlsh_9234b3fd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9234b3fd"
        date = "2026-11-02"
        campaign = "tlsh-9234b3fd"
        family = ""
        hash = "1526953e0d470988dc24cecde2fd149e3a91a6072c908527be767ee7e0b6c9db"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9234b3fd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{53F49750-6209-4FBF-9CA8-7A333C87D1ED}_is1" wide
        $s1 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s2 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s3 = ".?AV<lambda_1>@?7???R0?4??_ScheduleContinuationTask@_Task_impl_base@details@Concurrency@@QEAAXPEAU_C" ascii
        $s4 = ".?AV<lambda_1>@?1??_MakeVoidToUnitFunc@details@Concurrency@@YA?AV?$function@$$A6AEXZ@std@@AEBV?$func" ascii
        $s5 = ".?AV<lambda_1>@?4??_ScheduleContinuationTask@_Task_impl_base@details@Concurrency@@QEAAXPEAU_Continua" ascii
        $s6 = "\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome Beta" wide
        $s7 = "\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Avast Secure Brows" wide
        $s8 = "\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BraveSoftware Brav" wide
        $s9 = "client side MAX_CONCURRENT_STREAMS reached, skip (%zu)" ascii
        $s10 = ".?AV<lambda_1>@?CC@??_CancelAndRunContinuations@?$_Task_impl@E@details@Concurrency@@UEAA_N_N00AEBV?$" ascii
        $s11 = "\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 6691840 and 12 of them
}
