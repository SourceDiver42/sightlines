rule Sightlines_imphash_1bef5598_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1bef5598"
        date = "2026-11-13"
        campaign = "imphash-1bef5598"
        family = "rustystealer"
        hash = "03b942aa4b4c6c0548dc38838df4d0123022fffc93f37aca80892d6f15c4a404"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1bef5598.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "no launch path; PE_STUB_DROP_DISK=1 or PE_STUB_ENABLE_INPROC=1disk blocked (225) -> retry loadpeDefe" ascii
        $s1 = "RUST_BACKTRACE/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\alloc\\src\\wtf8\\mod.rs" ascii
        $s2 = "pathnodecryptsizereadauto1PE_STUB_DEFENDER_HOLD_MSexeqt5qt6libcurl" ascii
        $s3 = "pe_stub_fail.logPE_STUB_DEBUGpe_stub_die.logmid > lenwindow size must be non-zeroPE_STUB_SKIP_INPROC" ascii
        $s4 = "SizeLimitExhaustedErrorParseIntErrorkind/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\core" ascii
        $s5 = "assertion failed: self.is_char_boundary(new_len)/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/libr" ascii
        $s6 = "Cunsafe extern \"\" -fn() ->  + : punycode{}.llvm./rust/deps\\rustc-demangle-0.1.28\\src\\lib.rs" ascii
        $s7 = "too many active read locks on RwLock/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\std\\src\\" ascii
        $s8 = "<unnamed>/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\std\\src\\panicking.rs" ascii
        $s9 = "e.dllPE_STUB_FORCE_DISKMicrosoft.UI.XamlMicrosoft.Windows.ApplicationModelWindowsAppRuntimeMicrosoft" ascii
        $s10 = "Once instance has previously been poisoned/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\st" ascii
        $s11 = " loadpe failed; pack folder exclusion or PE_STUB_FORCE_LOADPEPE_STUB_DROP_LOCALPE_STUB_WAIT_CHILDPE_" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9903016 and 12 of them
}
