rule Sightlines_rich_header_hash_f4382dc4_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-f4382dc4"
        date = "2026-11-25"
        campaign = "rich_header_hash-f4382dc4"
        family = "rustystealer"
        hash = "1906d64b6be146d99dbc6c8fcb629b4764a74fa9df78bb9889cdf1c3bfaef087"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-f4382dc4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RUST_BACKTRACEassertion failed: self.is_code_point_boundary(new_len)/rustc/58cf8f9c35b355199727627d0" ascii
        $s1 = "SizeLimitExhaustedErrorParseIntErrorkind/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\core" ascii
        $s2 = "assertion failed: self.is_char_boundary(new_len)/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/libr" ascii
        $s3 = "Cunsafe extern \"\" -fn() ->  + : punycode{}.llvm./rust/deps\\rustc-demangle-0.1.28\\src\\lib.rs" ascii
        $s4 = "too many active read locks on RwLock/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\std\\src\\" ascii
        $s5 = "<unnamed>/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\std\\src\\panicking.rs" ascii
        $s6 = "Once instance has previously been poisoned/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\st" ascii
        $s7 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95b7-bb0abe08a61b}\"/>" ascii
        $s8 = "      <supportedOS Id=\"{4a2f28e3-53b9-4f18-8e90-0a0e85e7c29d}\"/>" ascii
        $s9 = "/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\core\\src\\panicking.rs" ascii
        $s10 = "/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\std\\src\\sys\\paths\\windows.rs" ascii
        $s11 = "/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\alloc\\src\\raw_vec\\mod.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 37426336 and 12 of them
}
