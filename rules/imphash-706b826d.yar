rule Sightlines_imphash_706b826d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-706b826d"
        date = "2026-11-20"
        campaign = "imphash-706b826d"
        family = ""
        hash = "1c04d454d6f461b7ad04ca1a2c9f88f6a979b1b3a0ec3e4e81ea8cfce5264dc4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-706b826d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "b9vJs7rzk8uFT1MbuvbD-2wevETS5fNzUSbtXQIxa4-0M3CHeypzAsVChMrLlAEIp7Lm6HW6QpgEncCMAFZGtK4dPpBeu_HYUZmL" ascii
        $s1 = "egOYbrxuunL4W6QLFEsqGJthK3Y_CHQ200c3wvAg6HW3PJlodOh0_umFKEpySMqn8GBzrci5T2-v05xBY-TXRPYianjOkU-rhLBZ" ascii
        $s2 = "KrGW15bwypHis-ZSeUV5Q5TBYzc9cvICJsLMaY5EDOTk-2dwA8O925gxEgNUFjtp75tTrmnCrosbAeTkjdFOf_eMqX6gyg4qkGnO" ascii
        $s3 = "laUBCtrLw0F9SII5G2DLLLuAmcl-Jz8EY0SpwVVCoieYjVom02BvE7ym4yTddCOr5bgfKQZ7U6a5HY2FbhkstlDXGqiZKbBHiyqN" ascii
        $s4 = "n there tfalsexuSOQT2CAScj_x3yDQ64q2MGX6wbAVk8WyBpOKEuk5tOlgwzP7U5f4qsRbGRPyW6ZnHyH1RJSmOkv5wN7cURzh" ascii
        $s5 = "YR6O3JILxcwupBf2k-aJPq2f1SQKvdFsYxenullzCJXAI9pjhLQf9DUFZQ6JbVPKjv5To1ZcCD-HqnZSqN0NcigXv0FpwhR0yQar" ascii
        $s6 = "EmxJdg4leX0jz61OwZhx8w1tNRFgpNlI_f4dg9kGDMry0SatDbroTHZ537QDdRbfxiPXQY9wkCks1QhqsvHYXlh3nMl84UnNJ1K9" ascii
        $s7 = "8cqgHmn7l4ZyBt5c4hbQnkH-c-1iLlKhIexVSFOCnoI0F0_ORZE_IowkjJ-bmqsB7UdwbeCY_RDowA9BPg2B4tFAHrhzG0SNPfcM" ascii
        $s8 = "HlAUInSczKn9JweAfYX3WGeiMn477OUFnoBQjCtLduiS-VEBT5lKMxrYBRZI5nCWvkM-XJZdNaK9QD9hT53tUlKqUEFywo_Xrv0f" ascii
        $s9 = "@?>F9NMhn2gKOaeLJLvPdJpTmxkfSMwf6Bw0VRJsMsl_8smmrKZIhqCapDcyoowYcsv3uZBwmlrQFriUXfDSrFhJ56wGjbiysLgh" ascii
        $s10 = "0hhVQGgEpjid5tVk4R11cECiojnSAM75di42Ug9eC4MNe_pwHtFaXicqpDTmtvf-N8dB6YBS7a_gZY0v5tsybpRh9enKL2x8G9hX" ascii
        $s11 = "wEOlSsQwu8-O5vFQ2fihQuXBe0Mp0Uir9mqwnW6oUlDRPD0Sjuag1NioW1fThCgcPsLJF3sPBTZ11IhmDFQyHg1GRkqYk7CK7U-R" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1233920 and 12 of them
}
