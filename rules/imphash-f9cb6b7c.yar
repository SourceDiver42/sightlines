rule Sightlines_imphash_f9cb6b7c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f9cb6b7c"
        date = "2026-10-15"
        campaign = "imphash-f9cb6b7c"
        family = ""
        hash = "63c546cf0f1c2051c734ec9ed09bbdf4278d55c4c0215f34da903a18701d8ecf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f9cb6b7c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s3 = "RandomCopyBytes: iOS Security framework failureRtlGenRandom: Windows system function failureRDRAND: " ascii
        $s4 = "js crypto CommonJS module is unavailableCalling Node.js API crypto.randomFillSync failedNode.js ES m" ascii
        $s5 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s6 = "failed multiple times: CPU issue likelyRDRAND: instruction not supportedWeb Crypto API is unavailabl" ascii
        $s7 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s8 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s10 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
