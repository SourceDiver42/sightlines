rule Sightlines_imphash_90ebd708_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-90ebd708"
        date = "2026-11-16"
        campaign = "imphash-90ebd708"
        family = ""
        hash = "51c133582379a15661ebde82cfc6f402badcf38b4bc11d143af430197525c12a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-90ebd708.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "kie, allowed8JfvcszEgTGbLrtrtfYhZqoJBa6I5O8VCJzXQK5f_NbSHkEQcvvPWcAYKP9zoE43Gsz_YceC7_w1Vw5KkI0mquD0" ascii
        $s1 = "4WGpyiFNo-lmW6-tr-o7c_PgjhxwDePT8_aHcXkSkfpnx6M8qnUbNu65_yTb1vk3mtJ5l-UD0h748dJEVaQZhwRI5ljmGH8-Dezq" ascii
        $s2 = "q8HGe4i5v_lUMxj4B-6dmRUO6ziw8T_sRe-3AlJl7fcZ6g1qOoVDtAVSPVaG8mEvCw0gLwElkSjWNdS8bFlo6aLQSDZNQGp2haUU" ascii
        $s3 = "3wZTnAsEzUtIVkOjwgrQi0aajH42F56qRJLqfHPs139eisVUCJfUolBo1qmZSOy6uUMU59gAfr1RheDLTemcC0IBmxNgMGrGuXcq" ascii
        $s4 = "d1twQz1GJ7euJNxsZ7dN4fYsabtBMCoWcHEUPhrc_ANxjNCvm3VSoKJyRKYlJZ2f-eBXny2GKkQvZXwLgqqD" ascii
        $s5 = "GPhXCuph2FWgcJVS_1lco8Qf_Ii1fx7dorE4Ulla-ZxBCjztjmmHeFuxa_n0zIwYRNCXUWQIFsC7OXWG2xlRyuHdLA-686LLbxIy" ascii
        $s6 = "X5utfmEcK-XGTddpp7YFUhjDJQTW4jCKesZmhUjzxQHBWa9d2v|nmdCtej3b-0rgobyj0JEIfoU_sJit_3a33MTkd__5lQlWFSA6" ascii
        $s7 = "gNg_rSi6a0MVgk7C33y2KlvUHyN3f15oo30h9sxFT-xOSWrT_3FhsoZpIuqwK8w765fe4jWGISKUmnhU8V8QAHvhD1w88S3EzXL_" ascii
        $s8 = "point1HKQdqnlaYPq0y17QeP1UQVPwHrmYqo0lg6tZl8YC5EOWvwLBmgu4G6urAfyBdDewUa3s4Lk_GVeZy3bUvbfMxPzxlfQ9SM" ascii
        $s9 = "rMuowH8eBtyzQrgSJ_MaXf_GoIdaq_tLhS-UzDp_RzAiZpNQZm-BnUX3gBcGrD5Ze25Zb4vPac8Eb23V3ff_X6jg4Kz1oIlWE4WR" ascii
        $s10 = "Tb_DdMptv1c4CP_1z7S6dMycoiWmGn_aCFyPf7ZxX-Eu-PKqNPMLrnu2Txo_kK9PHSBAGw17pmIvhlMqgfSFbvoJfZFXB2QqA34-" ascii
        $s11 = "ZA4P-5G9S8VfgdbU6o3Ti2s9TIetrIiDMPn_4Z9Xzrd5FwFvXVdmALXWgmm-LdvSRNDsOPMEywJ6C3KvJYWC5lXEsDbjOR-P15Gp" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1231872 and 12 of them
}
