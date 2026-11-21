rule Sightlines_imphash_92c8fa79_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-92c8fa79"
        date = "2026-11-14"
        campaign = "imphash-92c8fa79"
        family = ""
        hash = "00eb87ccdd4fd5cb4d29b5e270805c165d428f08a50aedf81922321f2a4b9a6a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-92c8fa79.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2sGZmv30yFZOH2GhSTYiN9ANzYFAndITl6-RQ9H-DdZvrJqDEU5RLjfLIPc9eBQxM6ot6cuZ_CYVekspnXWfxiBiN5uHYT1L9fSM" ascii
        $s1 = "2IwBH1CRuEwUHD5kY0KuLXnNhq2kauCX8ATP3rpctG8vR94ZqQ3jDvuiengieghvmMdROnpx0aQm6jj9L1g0iWJXxbFeyrJcoJIK" ascii
        $s2 = "-ZKWT9fLgvQWZEXRPqGX6rJeO7SrOk5Atbp7VKw4hT47hyOECPHaqv_-_pnMjx8b1PlRLYDrVoXNgTe9iMb9BU9b7tF-xZvaudhD" ascii
        $s3 = "VyGZ_0BhCxh-Y0qhw_hRb_4jiKz6hWx-hF97eetIrljSxg1H-QA0dpNySHOoCStDgnVNaU9h6s8-kH59w5vum35oE7leQqEMu1L5" ascii
        $s4 = "hxohXiPtmFQffTYJiu_5RuveFnOzzCS4DtR0a1QP27y5C_662L9fVgD9BcTcprREv9h8cgKEOzOz1fGc9HjIkqmDANX3QGwRvV-c" ascii
        $s5 = "bcYZ80dFHPyaEtH-sXmIYYI6dMLyH1XjKYHvOTzSDll25chR2S8PAu6Tw4yJbiaEzqvfoyIE9kW2aJd_VrasNPp7KPUsNmAd8e1o" ascii
        $s6 = "Q5FWhJm3wkE-UoK6cwXMXyWxm3_GbzsMV9fY1Eo9B2tlpMCg2zZD0IqVY4RZSSon6FTn61ugSO7-2YJNQkh17oV-xjOnfd4qn2_3" ascii
        $s7 = "XKjOWLRVB36LfmZ0HTn0P-mGMCVD4BgiY4BOWrqSU9fFrEGZ2Y3hT6eiyDgcjg7JQkCzQ0c0KaAwp8eG9wLQADTfL1Ey5liOq_wC" ascii
        $s8 = "GuJid09Gag2jHKeNNvAaI8af9gSo8u38-3YWAcM_s2B-UZp56K49Cwqrf4t8VpQE_Pny8rr0ZqnQJikRIJtVx5sw4iZ7hr-Mf_O3" ascii
        $s9 = "mjgRBcWNRIkWM5Lkc_zQHI0vXpfbuj-pTzFF7-xI7wSM3Tq--OnKfUgSknjrDi3nPnAcxuOQm0CihoDtxeytSsGW6NxXd3YKBqGK" ascii
        $s10 = "3XPKdSNYsXL4bhSYEYZo0bgzHp5JAQTzxb5GBHUgLQCOq-qD1nE-MKfep_VbJlkWNwyjtSp7aptL1_qS_Pf9TmBeYrafP5TcO1PP" ascii
        $s11 = "wFb5Vb96ddg-NPzDJyowGZHLuWU0zpizzmNlS38WgsHq7lh7w7Q07yqdhDwmc0Zn-4G8VNVLkP1chY6AzXBIOTWqxB0CEAhJKaQC" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1236992 and 12 of them
}
