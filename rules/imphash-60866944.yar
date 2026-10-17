rule Sightlines_imphash_60866944_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-60866944"
        date = "2026-10-15"
        campaign = "imphash-60866944"
        family = ""
        hash = "24f1dfaa9847f556973ea2443051646a3e6adf8991b3ef5e193e9642d8efaa8b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-60866944.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "window size must be non-zero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________core_____slice\\s" ascii
        $s5 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s7 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s8 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s9 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s10 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s11 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
