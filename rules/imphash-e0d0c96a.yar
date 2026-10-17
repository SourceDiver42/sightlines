rule Sightlines_imphash_e0d0c96a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e0d0c96a"
        date = "2026-10-15"
        campaign = "imphash-e0d0c96a"
        family = ""
        hash = "438f93bee0de18996480254eaa716c2d19673e6f237a5e943886bbc905b50f7e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e0d0c96a.json"
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
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
