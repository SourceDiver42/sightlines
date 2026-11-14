rule Sightlines_tlsh_cfdc72dc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cfdc72dc"
        date = "2026-11-10"
        campaign = "tlsh-cfdc72dc"
        family = ""
        hash = "84cd8bf6fa43ffc59f3fb3046933be0c650ef063a106b92b020580b51bdc9288"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cfdc72dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6BCRYPT_ALG_HANDLE_HMAC_FLAG2SafeBCryptAlgorithmHandle SafeBCryptHandle(SafeBCryptHashHandle" ascii
        $s1 = "(<>c__DisplayClass0_0LSumMarkeCayTryukAvtorUponGeckoSirenHon" ascii
        $s2 = "<>c(<>c__DisplayClass1_0PDazedDudeBirthEnjoyVaoEachLocFeuerFlinte" ascii
        $s3 = "FNanUmbauBidonLaiMimRepFrownBiserLapVFuelPytkaKhlamKnigaPegelFasanHopeKozelOccurPLovitLongHayXenVers" ascii
        $s4 = "&OSPlatformAttribute*ExceptionDispatchInfo:FirstChanceExceptionEventArgs&AssemblyLoadContext4Default" ascii
        $s5 = "NXinYeuButterEspeArktisAnhAnaiGeigeChastNTamDyraSatinSvetDochtTauNagelHaubeJungeRAbteilWanzeJunkIdol" ascii
        $s6 = "LowLevelLock ManualResetEvent$SendOrPostCallback8SynchronizationLockException(ThreadAbortException8T" ascii
        $s7 = "4System.Private.CoreLib.dllRShlemRaoLocGlobusDwarfDryanHarfeSvyazAzot" ascii
        $s8 = "ZShlemRaoLocGlobusDwarfDryanHarfeSvyazAzot.dll$System.Collections" ascii
        $s9 = "ISite\"ProcessWaitHandle4SYSTEM_PROCESS_INFORMATIONS" ascii
        $s10 = "&FrozenObjectSegment&TypeLoaderCallbacks$FunctionPointerOps[" ascii
        $s11 = "A9NQueueUserWorkItemCallbackDefaultContext<_ThreadPoolWaitOrTimerCallback" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6346752 and 12 of them
}
