rule Sightlines_imphash_7dde2634_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7dde2634"
        date = "2026-11-05"
        campaign = "imphash-7dde2634"
        family = ""
        hash = "0280901c2740795149dee80475e7819b8ac93a95d87413f15dd944eaad17a03b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7dde2634.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  !!\"\"##$$%%&&''(())**++,,--..//00112233445566778899cannot open savepoint - SQL statements in progre" ascii
        $s1 = "INV_FORCE_DUP_FAIL@[token] could not switch to process-primary before duplicating: " ascii
        $s2 = "RUST_BACKTRACE/rustc/88d9e12ae178fab0fb5cc050a94da85685d449ea/library\\alloc\\src\\wtf8\\mod.rs" ascii
        $s3 = "SELECT idx,count(*) FROM %Q.sqlite_stat4 GROUP BY idx COLLATE nocase" ascii
        $s4 = "n/MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINKMediaFoundation CameraCall to IMFActivate::" ascii
        $s5 = "V[unlock] OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_QUERY_LIMITED_INFORMATION, pid=" ascii
        $s6 = "GetAllocatedString failed - PWSTR is nullIMFAttributesGUID MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPEMF_DEVS" ascii
        $s7 = "ameCertificateStatusTypeHpkeAeadAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EXPORT_ONLY" ascii
        $s8 = " temporary filescygwin_conv_path() system call failedSQLITE_IOERR_VNODESQLITE_IOERR_AUTHSQLITE_IOERR" ascii
        $s9 = "assertion failed: min_bits >= MIN_BITS/vc/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ring-" ascii
        $s10 = "?) returned ERROR_NOT_ALL_ASSIGNED; trying user-process fallback" ascii
        $s11 = "forced DuplicateTokenEx failure (INV_FORCE_DUP_FAIL)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 13000704 and 12 of them
}
