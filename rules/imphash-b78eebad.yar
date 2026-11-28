rule Sightlines_imphash_b78eebad_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b78eebad"
        date = "2026-11-21"
        campaign = "imphash-b78eebad"
        family = ""
        hash = "1d5bfbee44eedefd4f2f30cea82b957cb0c3b1d0906d7cc90740579c407c097d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b78eebad.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1tSCE2Mhnay2d9bMVJL85P7WqAauaCxTuH_byfVtZGeWcbVHmDtJhcMLDR4RNo0-c0wE-YjodgKzQiCGX6HTZcvklOB1Snxk8j2U" ascii
        $s1 = "A5WBDj4R0sbInzS0dp9yJ_UlZCmZnvKF_u0vGlIqAEALtaYSpLQXk1R3HknM5MXmgqT7fCg8V1noDTHuzgApP3Etwz2NKI8tSgr3" ascii
        $s2 = "7jKKxgY4CRogscRHQnZqUPq9r7fQ7kbX8ItyfX-F3pnt00cSd4Tm5euiTph6c0PaSlOgVY_oNj8xm21VsISABeFBgrfMFdbfeb9g" ascii
        $s3 = "UYPahSTHVTzm082tNsJSw8gpRiyfc9KJ7W1qXDFwglutte7MTEOwi2Vie0eGgkrGdDc-6lg5HPoi_bDnYbQztyNg8.1SXv2G3tXZ" ascii
        $s4 = "UxfuZVbUOkm33r2Ca9ielXg4US7ljOZaRy2cPF5sXdEzCGYcew3VXQSPHN5qlRY_4PyafDs0dTTF6A1awa1taMJWN6bMmzcUsyhK" ascii
        $s5 = "t3Adqo2-NNxsbtPhg7Kp8_eOjKCB11FZRXJGAZxzyOLEnRkCSWoP2LPirlCL8XvthOwpnCCwf5a4_fbNVc5dl12T-MOcnIAoB4pD" ascii
        $s6 = "Y_y7mVr38HxmwQIRk5WolPJHgKOK68VUsuVOGhZPJYGC6Noxa0Li6iImFz8XlkzNOBb2dieqrljMrY69pEhHQcFGJ9QfmLFirst " ascii
        $s7 = "299j_CEkCd8ge5p3vTXHWc4Y2gVhBPHrrr52jV9ZnSHxYUfSNNTmFc-6xfiuqyw7365oW1ZdpflrOJa_SuXbZaKknzs2B-JOg2p_" ascii
        $s8 = "zyBN6F30Y4dJK0YdnYClk5vO0MsVwE958kfLNUKj031rlELfAh1rMRIrfUKZLtfMiT29Dp7jWh_JHJHNlebz97-AtSWQ9IcTRcNe" ascii
        $s9 = "2ToSe0p0tY5rOCgyGHbkJv6N_8al4PxythR6iK0ko9UqjV26re4vsjJWbALZBzzxTTwV_S57eLFI19_j4sOp50FqRACvFHEUh6Tn" ascii
        $s10 = "Khz8X7_5Sprgx2vEIder_tC9mjLAyDAZEiTODwEkmHsj2_DSCUmpKyXu5ldD17a-u8ZzWHGNPJrohxtvT_pb47O0JRfv7QI7KKwL" ascii
        $s11 = "yJ_kv9giRm37uIY53syDqzhvJpc4-07QN0kWzfRC0cIGFeSMufJX-b8UlYn9bz3Fi1JYxOaAg-Dp6ajy1-qZt5QT4c5bYCmLFoCi" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1251328 and 12 of them
}
