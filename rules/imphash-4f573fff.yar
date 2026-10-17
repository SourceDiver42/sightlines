rule Sightlines_imphash_4f573fff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4f573fff"
        date = "2026-10-15"
        campaign = "imphash-4f573fff"
        family = ""
        hash = "49075bd5d9382369b66d4fad8c5482647d361d0250ccc1cb82b09ba455fc93ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4f573fff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s1 = "i32i64f32f64StackOverflowMemoryOutOfBoundsHeapMisalignedTableOutOfBoundsIndirectCallToNullBadSignatu" ascii
        $s2 = "<assemblyIdentity version=\"1.0.0.0\" name=\"mozglue\" type=\"win32\"/>" ascii
        $s3 = "assertion failed: code < MAX_HUFF_SYMBOLS_2" ascii
        $s4 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s5 = "t overflow during multiplicationdivision by zeroremainder by zero_______ac68faa20c58cbccd01ee7208bf3" ascii
        $s6 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s7 = "RandomCopyBytes: iOS Security framework failureRtlGenRandom: Windows system function failureRDRAND: " ascii
        $s8 = "assertion failed: self.is_char_boundary(new_len)_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s9 = "a Display implementation returned an error unexpectedly_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f" ascii
        $s10 = "js crypto CommonJS module is unavailableCalling Node.js API crypto.randomFillSync failedNode.js ES m" ascii
        $s11 = "Utf8Errorvalid_up_toerror_lenNoneSomeAccessError_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1221632 and 12 of them
}
