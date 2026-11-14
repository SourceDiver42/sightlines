rule Sightlines_tlsh_e344100e_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e344100e"
        date = "2026-11-11"
        campaign = "tlsh-e344100e"
        family = "wardenstealer"
        hash = "0b4bf2bb5f727a956696316aba021adc90fb652f3a04b781456651cfc1925f0d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e344100e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "uw0gr0hgd4b4r2qvmv656tm93eybrx2we_6ec12kiwv1omxnj9y5wlnh0ncplpi3ctuodmhwul9xp55as9js31sjvi9ckgt_ojur" ascii
        $s1 = "csk2sjqjxmd2urm9q424ljx1h5tbeo_9awwq9rdg3ybcpcd2tdr1m0euhoiou59n544ngwy0khwh66llbablolsyvykg_tac43pi" ascii
        $s2 = "vlosky_5pqc1u3gyhiihwmmg229p44oibqvcbuoepasweeblt35jencqnsb646mjjxtg_muk0y06a4vh95hl1qwr13p3xmbd2ylt" ascii
        $s3 = "nahxge9ga3x6y42m2bgdevuoepwq3p0c3l_noa2l191r5ticvdw96j6ybeis0p0vwsprdvq4vhbkuipeh05smjuajja0torq_4l2" ascii
        $s4 = "v1kea1wc9c2wwr1gbka_3dsxn3mokvg55jb6ijyn0l6nednjmpymhca9tksh65jeyeqixgl4yuqos3ib2_rqjeysptbblx2uarlu" ascii
        $s5 = "eds20n_xyivdchbg0o39abw94q1mwrkurkbsikb146p2mi54rjlbj3cmlytkccaonul9_s39q26gqlsbv9em5ttypo1hrov9gh0q" ascii
        $s6 = "reqmo5ws2mpwlle0_dddejn5ui3h93cmqlchd4bgi0rkxxtyubenjcyx9n930cwp316ejbpkatcq24_5h4v5tukib0au5soevby1" ascii
        $s7 = "1b6khww16bam_j6rxq9itwobnln2au0jp309dk64325dpa0i5tkooi91dv6vuc9rvtgibhlpe5_c4x3gvj2qlshky4m00l5qvrqj" ascii
        $s8 = "2sicsgkybm1_jjvlta9m40vdo1rjpqqv26hdjmxydl3bok5m0oh34tdbtulpmx3hbnsg9g34e_xv6acncgknxq65ngw6arb9r1u9" ascii
        $s9 = "1mhyhnll3423wbmk6mp_4o69wkwkgmcj2uqb9aepyv40pqdwtrpa3eiqv1o9xrqsm13lsv515m1ip0nda_q09uojxgcvbhhd4wt5" ascii
        $s10 = "lksndmbvx_3u1prc4asc921xedqv4anrqntjmoswiy03ordi6u4sk9nbt50wyitgvtx9mqm_l0x1jgph0qqtu61kla95m3hokkjr" ascii
        $s11 = "qyl4i1n0vdksh9gbd4q6xioeo3hadhv_bu6r4tjwspibgcxm5195ral1quqkwks0pbunmohscjvjm9ti4snlyyn42x6jy_ehkhr9" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1527808 and 12 of them
}
