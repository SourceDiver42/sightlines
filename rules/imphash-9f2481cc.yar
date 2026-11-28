rule Sightlines_imphash_9f2481cc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9f2481cc"
        date = "2026-11-23"
        campaign = "imphash-9f2481cc"
        family = ""
        hash = "05fa4979e981595a785e5cf058f14e0a7fc2af318211505f4ca494df7b1ae844"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9f2481cc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "MsHe7wWirm1d90pj2M8entbhVYt6dr99VaI6zUA5G5Ku-T9fxxPDFB2a7z_MgzG6pXAWkHiSwtkqnbcXk44oXIZcRvr1cbjJHF9O" ascii
        $s1 = "-8zZ41uoeMYPg5kRGUeVkwhut8f4HCmjVLio3cz0XIIGtvAzogyjMQLND9UTGh1frdUNAbK7KcZPiXJ_EC29mm4olkWB_3D6ukMy" ascii
        $s2 = "2enFlnA_g7xwFpSyboiLGnull7EFPWMnbtax1T9SB2cN4PDuJaD4CL3m2VVcAYclFAzx0gf_50gvrkhq61J8dtwKy-1SWh83IaUA" ascii
        $s3 = "9mNiy9DGFIq1gQD6BM0kq6n5XBGUVoqQEDP9FNd_rQYxKXy2H5yyTj1uA_7BkEoJ6ctvrU4lL4WHtRNbRCI5hGdSeG435CU-cJTX" ascii
        $s4 = "FyRogOEeilGi3fUnLzAXx1I2Qa-5bAjUc6MmtITM6PnjuHaI4kkdhHicNJewtckLN1DGPPtSRVh7lcmB7OYVwO2JsU7naKMJAvdB" ascii
        $s5 = "0-x3-aSD0jnCVryF7K3glHUW7hnvZ4n6e6LhsyTXCqd9z1kpf1H7z-dK5bd9NQoknI_4KOO5NolITreEpmC2Cgr8hA26sMp_xQET" ascii
        $s6 = "SZqeLZljs0QaJq2BcC-E6AhB289nKKLN33FeS_PVrXKaKCM5iLm9Xu1-bwGfJHLIOTgUSij4JSOKafWho5glse-bEQs0xLD7DwQa" ascii
        $s7 = "07slsx5o3-5gVILZSDO5.Se_E5pa4BmgwGXurFF5GYeRXP0_GA8nPKD2kXTC32yT2pnNzNiMKC1cTKhsPFB9uvc4eAyc3Z2fIiwL" ascii
        $s8 = "BMkPJCBeja0eUlnrZ2wZbF_VLVznAwhE5d9ilBaMI4MPGjY9KyYMHPxmRplvr-Si8qG6_B30reRVEpkDCVF7sHcnfTEdE7Uk5yiL" ascii
        $s9 = "2jCstbOb-YPuSpKeAWXFG5c4LaAS0L-ovP41S4tHG0QFcM8G1qfKboPY6k1i0zWt1xoHzqIIGxZKT1jslUDmw4UPo_ETyJB7eagE" ascii
        $s10 = "bMq2Yn1nC8eeM12n8xdtLuoUuSQYEViXVGY7as4GNOTHEvQlic0zLTVQjqW6l3Bew5TpfrYyTke0WTNzj3BIlgKwby__vcpScRWn" ascii
        $s11 = "vsxSfYBcXCpId9XO38-qGqmvpoKoHhAuFFIgVrnY2wdGC8f3JUnK7zVkyEOJRd-w9CsxdzK6gMT5PoaUnObHa6K033v0W4rFSgLf" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1260544 and 12 of them
}
