rule Sightlines_imphash_5dea8a62_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-5dea8a62"
        date = "2026-11-15"
        campaign = "imphash-5dea8a62"
        family = ""
        hash = "7457d978da6bb136e927623c4f8f3114d2babf6db0086ffb216ec228969fccb9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-5dea8a62.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(JLsun/security/jgss/wrapper/GSSNameElement;Lorg/ietf/jgss/Oid;)V" ascii
        $s1 = "[GSSLibStub:%d] [GSSLibStub_acceptContext] after: pCred=%llu, pContext=%llu, pDelegCred=%llu" ascii
        $s2 = "Couldn't find MessageProp.getPrivacy() method" ascii
        $s3 = "[GSSLibStub:%d] [GSSLibStub_inquireContext] srcName %llu, targetName %llu" ascii
        $s4 = "[GSSLibStub:%d] [GSSLibStub_acquireCred] pName=%ld, usage=%d" ascii
        $s5 = "[GSSLibStub:%d] [GSSLibStub_getContextName] %llu, isSrc=%d" ascii
        $s6 = "Couldn't find MessageProp.setPrivacy(boolean) method" ascii
        $s7 = "[GSSLibStub:%d] [GSSLibStub_acceptContext] set flags=0x%x" ascii
        $s8 = "[GSSLibStub:%d] [GSSLibStub_acceptContext] before: pCred=%llu, pContext=%llu" ascii
        $s9 = "[GSSLibStub:%d] [GSSLibStub_acceptContext] set srcName=%llu" ascii
        $s10 = "Couldn't find sun.security.jgss.wrapper.NativeGSSContext class" ascii
        $s11 = "Couldn't find sun.security.jgss.wrapper.GSSNameElement class" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
