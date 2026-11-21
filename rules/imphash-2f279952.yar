rule Sightlines_imphash_2f279952_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2f279952"
        date = "2026-11-09"
        campaign = "imphash-2f279952"
        family = ""
        hash = "0c8ec0555116b101b7ba54b1fd5fa08ed37b49400ef6824ed46f8e3377940211"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2f279952.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "zdWV9acMA6-QBPZKr5sS8uNwnlG2YEHkiX717H1vGVlqj_hFURBTb1ODRDYgS-yq-KQgl8HoZLpLN3MbHw9AUx1nX_s6gcer9gs7" ascii
        $s1 = "KSf4dboIzaMuzr_0JSFH7ml9x1XTyJoSm0JIpLON0KFjU5NdPhbUFGw91olSCZsjvsOicpW6AZwVMc57HkApMwi3ELBY6zDryD2F" ascii
        $s2 = "XDFwnj0R-ClE7e8ixK3K9IhQG_zjWKLz43ulW5kIBvfj5hOGZt-Hir5LdJruoCA__5FvrMMT07m8bACcv2UXwhE4p4O6FFe134ga" ascii
        $s3 = "Pj9ceb7gaW-_Eu9XDtGVDYrmhBZ5KMm6HDr3m4upVKoewX8RY3qnVES1g2aRGXveTBIiN0tAMnpW-Xn_1iSS_LdfzyBn9wekFB0g" ascii
        $s4 = "4U7dvofhS1IEX_6tnjzwM2hN-GZyWZufqDNfJvubXr-s5HUj_0fB2AyVOnPII6Oe3W0ZVptDEqweyl4R4f8OPmCu5ougakjbWEKe" ascii
        $s5 = "zpp1Anu-6kwUix4UH6YWi4yhSgiDjXBvD8Kg0w9IAh6SA77BdqIAk0d5gr2cMaW4FKkbboS8aTJlBGOUukDcyKEeXrCY_0ZLlmXr" ascii
        $s6 = "Mk5nl8NWtg_aEuzuXBW3ON8u6egD4jD9_ixYGRXAdSELyz7KmZAxNJv5ms1TC4jgzv0G-0cBM0Kgp3G7jIk_JHiaVIlBnrRZyyXY" ascii
        $s7 = "1_AVwYmZEB2pGCx0qO_gocKkTea2votH37laO9xPjNLoYWFsGM50_s0-8Wx2OsMjySw3T-XU03RnXgJcRryDIJxuj0GrlXwIpPsn" ascii
        $s8 = "2aV_cas9h8ejIxqAo9NhLXnxsexRy7j8ree3rGxgREnlMvBd08X--u_M8htTPobWD240fAuoLwxtdZdqn34BhGkOBJPJSBp1zAiU" ascii
        $s9 = "58268edYCmy4bkCa46L_nuAtFzNkYjFDX_cWaf-R4Ve_gihxU2vEJ6GNGEPNvOFjN1oDw5jUt1hagKib707Wpu1-fKdu2-YQ4qAB" ascii
        $s10 = "15IT7QDhsHWi3PzZf9V24qt8FzNy_fDp1QLCUgymS7Xc1god4nDEfLi6HG_6XraqaLtUcQAdFJkaCuF_4x3dj0SDiV7bJdv9udc0" ascii
        $s11 = "false2nBkNhE1pFJ2ov0L8Ah7nP-t_wYzS4B-TatXWVlzJ5_pq2OJU7dSFi7LXcxLbImMMZjCqpVg-RgXNl_2WkAXMGnXLt7CUKN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1204224 and 12 of them
}
