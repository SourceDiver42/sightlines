rule Sightlines_imphash_a2f38bea_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a2f38bea"
        date = "2026-11-24"
        campaign = "imphash-a2f38bea"
        family = ""
        hash = "15088f5d3f18f511c5053199f7ee90da05da615574332c2cef05c284227bf1ae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a2f38bea.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "7yFPILAuMoRQendsiactPDt9rNlh-Z8-UrYcJvJRW0FZElwCSyTLzVWRU6bBx5__xqYrEvzKfw8SeQd2i6lRvNmQJlBYX9L7man " ascii
        $s1 = "GfkCtyHW_1Y2btDNeqbp3F9EQNbOiwR-abpM32nwM3cILILapZ8VcKUok0Ij6v5LfxPPglAm3WgMotugm4Xkw8jK-JIxT1Y2iD0N" ascii
        $s2 = "EOrB6lPRrdWKFXT1K3bTjk7A54slqr1pvOwCiSLfZ1cPAfv1UP0GPJcrOxVoU2HuoG97tkVG2tz8NKb-Lz_z69a4J8zJ9MMsnSBN" ascii
        $s3 = "eNXpZQg8_iv5kMZOnhHqHri9dWBt7esufTU45kk7g3-5y8vvVGPgGDdIoISqtnamOuaWyKOYHfi-RXc2RjghnL2x9PE29CMTYHmB" ascii
        $s4 = "be3VblmTmYXgx0I9q40IX3a6NX9loG4FuaJPKtcfBYrwZfp1p4h7BBe5kDDESgxZs-5Fa3vW6vkmuQOUuZfQ7_GYt6CAJZ-zobLW" ascii
        $s5 = "6HV_J15SfATBiF1NhJUDm-UQXB10mhCwHVRr7LRe6ZRG-yLnr4xFaGsXF32yjI8vLeQcyVVMLuBWbKSLZTv52rdoes know must" ascii
        $s6 = "R-zch9muqbSA-yp8Dc_vzJseympPNfyr8e3L3s1iUMg-YDGfw_7zLJ00dC9E4yjm05TWdFDIBfOXHW_Kym9GRt6ZrtOLsw9BiKam" ascii
        $s7 = "WmOU8XPn_CEnMbD4gIZnXeJAbhgiSSV6HwdVR0ZryR4EtFQq0LmcUjMQEYJLM_atp933nf1O_y34mzNeYJaNCX6B2o7PfPQQI9xa" ascii
        $s8 = "kDcprk7rIwHc8x19gjb_WNxRaqutiX17nsRkrmoLOayShRnKqujDxJWZSWM_osfy0ButzMzVhngKF42sJiR9QEPQZvV5_wPElQn0" ascii
        $s9 = "eoYjX6XXneiqg8lsSs-9pTmwd6VdWtU_ztEZDWMWkp4ngpxEnB2q1FB563aKG9xh8f7yOj42kvUXcghQ7v2UVM7been form mak" ascii
        $s10 = "ZBe8I0_Lwu4D5n_z79qCq2pAyYO94gyyuzcCd8wY548xAEOFeC5lu01zJKRNBZN2Nbou2JHQi3G8Ti0r2STstWX_fRvVUyZK80Gm" ascii
        $s11 = "TyXQ2r7xKOPDdmCoSmj3xOjHoseixUiswK1zysVFp5Wq-NTjyHq9Wd8ZbExzT0RJVy1DBIRdiBlLEX9J4el3fHpetmA9*oG5luXu" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1260544 and 12 of them
}
