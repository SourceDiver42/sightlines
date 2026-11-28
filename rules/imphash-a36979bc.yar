rule Sightlines_imphash_a36979bc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a36979bc"
        date = "2026-11-24"
        campaign = "imphash-a36979bc"
        family = ""
        hash = "12eee773cdd783dd5052463d8825e89cd3bf8f3bcc58dbb87708bb70e0a73713"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a36979bc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ITEKvXW-8jiKN97j354xi7CxpBlbnGQN0BmR_O1hIdUA_U3OCjBVMAeNdJCOff36nLkgSv1U2wZEbygDoT-vW-YkGCH1dj6oeMEc" ascii
        $s1 = "S9-pMsawwatBnMmQKxlvFCZfYd4BRhpBp3rDyOyIPEARbrfY8Dr91W2z3GexsHte2T16zEbuKlTHXRHkgzO26le0v0_d-YMIEL7-" ascii
        $s2 = "mKn7MERzt0AhglGPvE4L9YfDflSsxJbQyprBe2DW8OhC2qy9kSxXM9N9nGLZaOlpYr2Jx3VE9fSaz1pjopmBFvu-no first wen" ascii
        $s3 = "P4aD2wmGnjOEt0ywgBbYmt0DiDNvcR2duSIr2G10yBkbgI8p0ttxm1_SQA5e0FHU5LwfECB4xtz_aAyYM6h6G73sCq_8l9QlCoaI" ascii
        $s4 = "KEfO1-FnlsRjcCdN6Zvy4qj8VMzYtTUw66r-niiPFSb_XIATgIQnedHvp_CkEJF0JuU-jkJ-2MnOLABNUPrWyQreojS_CJ-e5va4" ascii
        $s5 = ".uUiDALmjVG4oD0nmqu1K8C-vfCSYnNIafW0abzpvzJ194AemeXxHc6JVwkL0V2jBYHlKIqeM5W7Qm8-qODD1Ctv69Q-xTSfdkg-" ascii
        $s6 = "zriIoz7lMUWnsv2PC9YfdaHUPIIjyIO0tgGAE3jUl7QK76hAnhaL1D7WkakLW73u6f4Y9zTO7Bv-0qC2MVGRmNaZb_-9eG2XQDRB" ascii
        $s7 = "2QIIrfhkxplG2gKAosHq5YiYaETS10o7oq5rGTiv6sY6eC0JoXmcEP1muwFpyF43bqoOg9dhF67TNQ5GLtuLtYNxIpknZlM_5g87" ascii
        $s8 = "eo7VdDXnFsAIbkSy_RzWugmS8NY0gtBMiyp-MqYKEtGvMPM9VcqrLYLoxF-7j84QrUU34YA7N29e3qKG6-2uvMBUJfO4v9M4HO63" ascii
        $s9 = "tionpoA_RwqtIANGKkl2GPbxaZYNO6cHkyyyKZtEfBYuC_1MdLbVQ4B7-lia97rNJpaSPaqzyF3oUq48tcXmHu7K-kECwpv68myz" ascii
        $s10 = "69ndeQba3ymtmPSnLFvEzwDsc6v0f2Oet6TkTI4GI1MKUqDyh9Gq2jNHArn8oyTHOxvI77fV2O06LYNo_lW7Oq1DzLj-WEUbWkI5" ascii
        $s11 = "cYfPst8z3K2GvwuJXoQZtYV6LBIOxCAdazEy2sKHw3WMTNc0cKFZn7jv8U-J-ddiEME_KZwg-DXbinStSzWkvOKnE_9v2epLGZ06" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1240064 and 12 of them
}
