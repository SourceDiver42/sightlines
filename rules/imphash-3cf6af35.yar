rule Sightlines_imphash_3cf6af35_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3cf6af35"
        date = "2026-11-16"
        campaign = "imphash-3cf6af35"
        family = ""
        hash = "03fddbc33a7330ffca7ec352be00365595dc1c8afde29131b2d23666bd14a19d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3cf6af35.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "3XQEwPUwBNdanl_4BxJDFxJHqShmTbvti9zASl5YS6rzZ4YOXGC-p5IL_uKzyF67fGV_p2Msny6cLUTomow0GlvDG12Zs42q1hpB" ascii
        $s1 = "YawVrC77gxYvM4_VWz64ZureqK6-uLxnMlGdjHK3XHeDJQO5BVkNXSBCvCnf2nU9pqDAsKBPpyU0StXMd7O8sIdiRgpRfwmzH7iy" ascii
        $s2 = "Lc_rRZCOmBxCdtY5FsgnCMHhyiDEqM-aJKL4SRL-ynenbGfpSl3GOb7_0dfdQknbQejPEZJAjIQ6DcKNo6rNWZLCVyvXHmt7ivEf" ascii
        $s3 = "ko91LralbpjBwFxvPQvceIRl_GPfOeD_GnNnBUwNBi02yldcPdr4q21Zp3atU6eWPWklVMmXBWl0WQAKJs4-ivtzER41dLRJuSEH" ascii
        $s4 = "EQNhIQo2KU7ZwqwcjdRs3dZVVt5w0dF1kCA_KijibzOQ6LmgJzqCcFXgztrue728fhSxBsgAoYGTwPjJiIwtuser callback fu" ascii
        $s5 = "@?>F-XM_0xudGsuLaJArFFStBSi8c3a77msfvvfRpMCyE-k_TH5ags_1Xjx2dhUgno01suHz5FXlgmzWYcnkgPsmTnGSPpDbIDPk" ascii
        $s6 = "zoi-gkC6sL5tbscOUGDPtXj7RaUnQnltwK1ODpM24DU3iQkdI8AqJQkiYuzYFwruienteiarlycBR3-b3wvfSPLIss9TXn6NClAZ" ascii
        $s7 = "meBW_lAJxiIygh-35zHskolqjULoK2P6j-m2jf75DLVsBTLsGpdv6nTpPAfYgP2ACE-USYt-KZZYEMxmd3fMb_G90_St8-NYSXw2" ascii
        $s8 = "8gIRNmyWUHKqjQOX9zscF_n_0inOppiY9mUsCE8_tcvf2yT-7kkWsDFnLbFk4Ms0cxoqUz-JESaG_AeSIE5AuFliNUxOZFdikBI_" ascii
        $s9 = "N-2oogyIrAGy7CsW7BWQVNvbNJks6g5RAnvpBlLRyfE77BdQ_6Ekizt80ug5SHzcrfOQ4QEnP-96-pq2qlxaxoaAa-yjA1Um3Zbd" ascii
        $s10 = "ROngNpDyRlIzCS9KEtK08p3FeFhqkh_6o7W80KZGP8rj1YnLo9ItNWZnteU0edOOcxLSPNMkNmTQMOjQ94t_2isxiCQ4qO_mAfv3" ascii
        $s11 = "NRMhFog2cTJV2zwigS_vOqaT4n2_Aj9lzPHR3A0NeodKqk34yeDpYTKCM6ehfevZ4ulXz5i_a0uQcre95OLDOisQCYsBlrxjCf9M" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1236992 and 12 of them
}
