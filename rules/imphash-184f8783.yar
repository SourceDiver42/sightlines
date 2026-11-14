rule Sightlines_imphash_184f8783_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-184f8783"
        date = "2026-11-13"
        campaign = "imphash-184f8783"
        family = "wannacry"
        hash = "321ecb0d9b2f1cfef92ce76dbae37adaeb78d16af81eb3d7e20258031afb75b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-184f8783.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "- unzip 0.15 Copyright 1998 Gilles Vollant " ascii
        $s1 = " inflate 1.1.3 Copyright 1995-1998 Mark Adler " ascii
        $s2 = "Microsoft Enhanced RSA and AES Cryptographic Provider" ascii
        $s3 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
        $s4 = "oversubscribed dynamic bit lengths tree" ascii
        $s5 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
        $s6 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
        $s7 = "Global\\MsWinZonesCacheCounterMutexA" ascii
        $s8 = "$8,4-6'96$:.?*1#HpXhA~SeZlNrSbE" ascii
        $s9 = "icacls . /grant Everyone:F /T /C /Q" ascii
        $s10 = "8,4$6'9-$:.6*1#?pXhH~SeAlNrZbE" ascii
        $s11 = "msg/m_chinese (simplified).wnryR9" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7028736 and 12 of them
}
