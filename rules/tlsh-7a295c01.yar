rule Sightlines_tlsh_7a295c01_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7a295c01"
        date = "2026-11-05"
        campaign = "tlsh-7a295c01"
        family = "asyncrat"
        hash = "40618793adac69df00e5fe836827e38c13c2f6452d42e881c8efd256d8bf0c63"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7a295c01.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "HZjMUJCWjBsRFFXeDBaRmhHYmt4M1dXd3pORzltTUdSM2RqbGtLMkp4T0VwUlEwRnNkamxrSzJKeGNreEVPUzlXZGtKcFpqRllhV" ascii
        $s1 = "TI5c1NFTnZiRU5DYjJ0SGFXOXNUMHBvTkU1MlZVbEpWVzFvY3paeE56QkJkMHRLVm1sWmJXZGpNemxwVlZsdFJIVjBaMU4yYmprd" ascii
        $s2 = "HZUbWhrT0VOQlowbE9kRkZXYjAxc2FHOVpOSFJJTm14eFNsZ3JiMDUwWkd4dlpqUjBaaXQyVTBJMGNERlBRV2R3V2tSWllYaEJaM" ascii
        $s3 = "VROS2RqRXpTWFl4TTBoMk1UTkhiRXRLVW5rMVF6bGtjRlZIWTBsb1VuazFjVnAyY0U5QmJFdzVaSGR5Y1hvM1NEQXZXV3d2Ukc5e" ascii
        $s4 = "VRGSk4xTkJTMEozZDJKeU0yaE1PQzlqTjA5V05HNTFaMlUwVjJreEx6SlpiMnhZUTI5c1NVUnZTRGRCYmxreWFXTk9TMkZqU1dGb" ascii
        $s5 = "k54SzJkalEwRnZiRmcxYjBoSFJXOXNaamxuU0ZOcFdHWTJhVEZtYldreEwzbHBWV1UyWVVGQ1lrRm1UMHhrTDI5T2RGRjVURlFyT" ascii
        $s6 = "kJ0VDIxdk5tSnFjSGxQYmxrMlpXcHdLMDl2U1Rab2FuRkxUMjgwTm10cWNWZFBjRzgyYm1weGFVOXhXVFp4YW5GMVQzSkpOblJxY" ascii
        $s7 = "jBiMFp6VmtaQ1owbERRV2RNUmxKUmIwTkJaMGxETm1jNWVpdDJNa3BXZDNGS09HeDFTa05KYzAxcFZXZEhhVEIzUjJsVlFVdHBNR" ascii
        $s8 = "XQzU1VOQmIyd3ZLMnBJUTFWc1NsTlZiRXBXVmxBeE0wVjJNVE5FZFhKd05TOHpPV2xrY1VneVVUSkhNbWRKUTBGeVowTkNaMGxEY" ascii
        $s9 = "nhIU21sSk5XaFhXVVJCWjBsT1oxQXJXVUpuUzBwQ1dYVmtLMmRKUTBGdmJFTkNiMmhQVDJjclNtUnFiMHRvYzNOT2FIZERXa0puU" ascii
        $s10 = "E5xY0ZkUGR6a3lRVmxzUTA5dmRHRkdiMnhIVDNkdk5sWnFjMUJrWjBkS1VXcHhTMVZvY25CTFNXeENRbTg1VDBwb1NsUnBVWEp4V" ascii
        $s11 = "FVNVGgyTjNSS2JqUnFORU5LY1c5QlYyRXZabEJVU0dodVQybDJPV1p6SzBGMVR6Vm9kaTh5TTNveVpUbHNUbGxpWlZsUVVIZEtje" ascii
    condition:
        filesize < 5119748 and 12 of them
}
