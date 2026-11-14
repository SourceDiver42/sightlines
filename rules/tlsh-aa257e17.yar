rule Sightlines_tlsh_aa257e17_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aa257e17"
        date = "2026-11-13"
        campaign = "tlsh-aa257e17"
        family = ""
        hash = "69293fb052f8c01e85a871935ec9efbe28188556974dcdd42b76395422284782"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aa257e17.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$RuntimeClassImpl@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00$0A@$0A@UIDOServiceCallback@@UIDOS" ascii
        $s1 = ".?AU?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$0A@UIDOServiceCallback@@UIDOServiceC" ascii
        $s2 = ".?AV?$RuntimeClass@U?$RuntimeClassFlags@$01@WRL@Microsoft@@UIDOServiceCallback@@UIDOServiceCallback2" ascii
        $s3 = ".?AU?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00UIDOServiceCallback2@@@Details@WRL" ascii
        $s4 = "ce_policy@PEAGP6AXPEAX@Z$1?CoTaskMemFree@@YAX0@ZU?$integral_constant@_K$0A@@wistd@@PEAGPEAG$0A@$$T@d" ascii
        $s5 = "policy@PEAGP6AXPEAX@Z$1?CoTaskMemFree@@YAX0@ZU?$integral_constant@_K$0A@@wistd@@PEAGPEAG$0A@$$T@deta" ascii
        $s6 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s7 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList" wide
        $s8 = ".?AU?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$0A@UIUnknown@@@Details@WRL@Microsoft" ascii
        $s9 = ".?AV?$__func@V<lambda_1>@?1???$ExpandEnvironmentStringsW@V?$unique_any_t@V?$unique_storage@U?$resour" ascii
        $s10 = ".?AV?$RuntimeClassImpl@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00$0A@$0A@UIUnknown@@@Details@WRL@Mi" ascii
        $s11 = "Overflow/underflow encountered computing position for CRC_CHECKSUM [%x]" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
