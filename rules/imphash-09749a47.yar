rule Sightlines_imphash_09749a47_bridgeagent
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-09749a47"
        date = "2026-11-04"
        campaign = "imphash-09749a47"
        family = "bridgeagent"
        hash = "45d517f0763d89472a30c486049828f87f2c80915bf964ebe41138b5c3aee1c2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-09749a47.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " helper thread complete[DEBUG:MAIN] Waiting for TRANSMISSION #1 (T=90s)...[DEBUG:MAIN] " ascii
        $s1 = " FAST thread panicked[DEBUG:MAIN] Waiting for TRANSMISSION #2 (T=300s)...[DEBUG:MAIN] " ascii
        $s2 = "RUST_BACKTRACE\\lock count overflow in reentrant mutex/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea452" ascii
        $s3 = "OMPLETE (T=300s) running in parallel...[DEBUG:MAIN] Waiting for collectors...[DEBUG:MAIN] " ascii
        $s4 = "RUST_MIN_STACKC:\\Users\\Admin\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\tokio-1.53.1\\src\\r" ascii
        $s5 = "assertion failed: DEFAULT_MAX_FRAME_SIZE <= val && val <= MAX_MAX_FRAME_SIZEC:\\Users\\Admin\\.cargo\\re" ascii
        $s6 = "privileges.txt[PRIVILEGES] collected[SCREENSHOT] stubSensitiveFiles.aws.config/gcloud" ascii
        $s7 = "Invalid AES vendor versionInvalid UTF-8/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea452/library\\std\\s" ascii
        $s8 = "called `Option::unwrap()` on a `None` value/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea452/library\\c" ascii
        $s9 = "127.0.0.1:34254socket != -1C:\\Users\\Admin\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\socke" ascii
        $s10 = "[INJECTOR] exited cleanlyoutput[INJECTOR] copied browser data to outputUSERPROFILE.sshSSH[SSH] colle" ascii
        $s11 = " COMPLETE thread panicked[MAIN] cleaning up temporary directory'[TIMING:SUMMARY] Total execution tim" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 22084652 and 11 of them
}
