rule Sightlines_imphash_bf1281ca_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-bf1281ca"
        date = "2026-11-11"
        campaign = "imphash-bf1281ca"
        family = ""
        hash = "8cd73535d72056ab18f08112c5274818cb8842e757d299dcc7ff870d62bff8e1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-bf1281ca.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJJJKLMNOPQRSTUjkVWXYZ[\\]^_`abcdefgh" ascii
        $s1 = "&%'&(%)%,+-+.+0/10203/4/5/65768/9/:/;/</=/>/@?CBDBIHJHKHONPNRQTSUSVSWVZY[Y\\Y]Ya`b`lkpoqpsrtrutzy{y|{" wide
        $s2 = "wnObject\":[344,\"GCHandle\"],\"LinkNext\":[120,\"pointer\"],\"ThreadLocalDataPtr\":592,\"TEB\":48},\"ThreadStor" ascii
        $s3 = "g\":64,\"_remoteStackTraceString\":72,\"_HResult\":108,\"_xcode\":104},\"ExceptionInfo\":{\"ThrownObject\":8,\"P" ascii
        $s4 = "TAStackCrawlCallBack: STACKCRAWL method:%pM ('%s'), offset %x, Frame:%p, FrameIdentifier = %s" ascii
        $s5 = "oken\":40},\"FnPtrTypeDesc\":{\"NumArgs\":24,\"CallConv\":28,\"RetAndArgTypes\":32,\"LoaderModule\":16},\"Dynami" ascii
        $s6 = "ReadyToRunInfo\":608,\"GrowableSymbolStream\":336,\"AvailableTypeParams\":528,\"InstMethodHashTable\":584,\"" ascii
        $s7 = "EnumMemoryRegions(CLRDATA_ENUM_MEM_HEAP promoted to HEAP2 via DOTNET_EnableFastHeapDumps)" ascii
        $s8 = "reviousNestedInfo\":0},\"GCHandle\":{\"!\":8},\"Object\":{\"m_pMethTab\":0},\"String\":{\"m_FirstChar\":12,\"m_Str" ascii
        $s9 = "onNode\":{\"VersionId\":16,\"Next\":24,\"RejitState\":32},\"ProfControlBlock\":{\"GlobalEventMask\":1888},\"Fram" ascii
        $s10 = "gException\":1350},\"ResumableFrame\":{\"!\":24,\"TargetContextPtr\":16},\"HijackFrame\":{\"!\":40,\"ReturnAddre" ascii
        $s11 = "t\":1768,\"HighFrequencyHeap\":696,\"LowFrequencyHeap\":688,\"StubHeap\":712},\"PEAssembly\":{\"PEImage\":8,\"As" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 35516140 and 12 of them
}
