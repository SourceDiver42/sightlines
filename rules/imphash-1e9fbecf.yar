rule Sightlines_imphash_1e9fbecf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1e9fbecf"
        date = "2026-11-17"
        campaign = "imphash-1e9fbecf"
        family = ""
        hash = "0cb53d666d2819ec921a73146c523b74bcef7419e8af8fcb8b675bd4d8389f53"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1e9fbecf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LwSIj_7xjVaPbcM-ePAiYHUPLbX3Ot29dp-qGyfwOwO8cRMi9Zmpk9VAQZ_sWJkJjps4XJRWTqErpnZh32zoX--QsFQlmKtB1HC6" ascii
        $s1 = "LQENpNjlVuhwU333xB18PW0XaUuKHITw60JMBAndSG1OMgKmk9nYKAstNqKY__FJUDjD9NvYQe_6_z4dHLMD4-Mcro9F4HG2Cb-A" ascii
        $s2 = "n_qMyqyIx9CQGA_vMTGNvkcXAErsfpf50Pbzoe1uVUDxo4xm6ZZk9cO37M_42_7jlWJ7sagNrM6FvNrdTSXrnUl0Ybq3zrPORi4i" ascii
        $s3 = "*10NRVxze8x_G0nXla0LYX2J4HkkmuP96NiAXLUhIKbNXLcU5KvzoZ23wHck3TVWPyxL1hI6kardfwdVP-lTXzp5kADmnjqsGB-D" ascii
        $s4 = "WlmCQ30EpmQ73a_xoomjpy712woLRB-cvCyfXKwGnXnd4ARKCF4NsN38B01aI3hSucNwRkJ_DbUhLfKlQGzztA6ADYTOLIM8U6b8" ascii
        $s5 = "43e1E3KmUH2zYqyo7MLXN685_e9UJA5Wob3gsq4ZUl_nDBjm4QC4VSPw-sNDfofOT8CH5BQtHXRdxyXq7l_RjiYzRvWm_lUkqVQa" ascii
        $s6 = "TzatZYbUGlDC9VeP_pHcV2g-AVy4K5PXC6pJ5EXjI6Ex_6rk7eOsQoG2v1vRrqaLZ-v3J3hWQ_lzfTQALczUtmRErjUogRFjIDUz" ascii
        $s7 = "06ZVbTEU_aprf_1S6sbKdC-XXh2IvXJFUyFlwfsjLZP5s4CqkzhAV855Y3M6EzkxEZg9aP_QmduFErRhTWrlMk1r_HOC3aCYvBJc" ascii
        $s8 = "85FFWngcfFv_g9nvA-1YGLoU78l-BNtZIsoyewmBJSLTyE4_2XQWFGk9hPTyj6SzwTKd_H23xx58C3Xd2aPWSbBPVMxQoT5yxAbV" ascii
        $s9 = "7MUii6U_nm3JtDL0rE5FeXaolN1ZbkNOKGT1vdRWyVVe_vk8vofnfubSkC8-rZx87TxVj5FkJiqMzM_yRVosncZjfTaRwG6QIFgs" ascii
        $s10 = "O2iU3Q4JjCgI57AoK4IJ3ruzg1JK3KWfimv-cwHZLqjq60Su69hD8UBDBdZDt19aN5Dx_UcKnYOy26TlgLqQ-1t2EL9zMZJP1sQm" ascii
        $s11 = "-rNmSoWaNB8VE1hQ40dQ40esp7ezjLFuG_bn8vq4_yW171RGnLb2T65tjgF9jZl6wHtJ8rGSX0psC7w9YCGE6o7ZxQdjagO2ZJdM" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1187840 and 12 of them
}
