rule Sightlines_imphash_d738d2fe_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d738d2fe"
        date = "2026-11-13"
        campaign = "imphash-d738d2fe"
        family = ""
        hash = "0550e097adc22f8639c962cd0a5408d83afe25823d253af0c67780b5132ac142"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d738d2fe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "htnQOaPlAKXSax8ZiIgd_2VH6FwYcF6sWvndQnAaqrciL6Oo_0DBluK7yshEIpsB48P2kDokczgYCV1PeJt9X4yUdbAsDEmR4dyr" ascii
        $s1 = "aY37UOcJAcpC5JM5bUvhc3vtdc_6s12exVQu7hPGjR1xJ9VDUKBLgT0GfQQ6Nj5oZivlKLBHmdN_-qUI8cP9A8AmW6QzZaUXy-R3" ascii
        $s2 = "FNUc5_0RPoBMv2RUw6xsJbX8yQQxT21TXHiGSO_V4LB7VMb4_V684dCblcd-PhqKjQaYskv2noJ7mqpZeyXCUHOGGEcmAyKlxf7v" ascii
        $s3 = "R7c1r_2_eXySWIodU5UlAcZHf1lKUBVmY60BOcFHDNES_NWw3EzjmAffu2vySIGIQF9L2aLh4Tx5xKy0_opkAxd5WbusW5JT9lZn" ascii
        $s4 = "nKovcyiY8bxkbPp2GpOLfgBsiIGgQLN-lujRHEdJTpOtyeZkZSsRo86wrSz4ATPoG8qoSPyT0n_9tze6j9PCT93eHJbMnc1O7uNF" ascii
        $s5 = "fpktMec0qMH3dVGOv1OtWhmj8BuD6sTcXzlaSkYEhu1DjNgyIZdBQAfu7Nnp-DaHWioVArv_7XWZ2KjauP3s7H8307-dUMTLA0zM" ascii
        $s6 = "tEHM0tRsxtfrPh59wrGuO8mTt0ARw-DjaB7owpgg_WoccZoPjBFYrefPLAXaSThC0N6pXY54Kf1dTkhiLq1X4JYmjVXgQNTgB_pU" ascii
        $s7 = "ssCxNiB_6QjyI9Rds5yyuZtH0cFBc9TiOkzewfTVebyCQ9Zc8rPpjQatzatVAJ1xC9kqlh3NUf1heIQGn4wxERiuYoK7hB-OKVGG" ascii
        $s8 = "u0iNf9LAQyW9_aSXkJoUEfXHtuVwLSfUjRYs_wBP57w-_IBbIagobbTXtBQRD4lrOqzqLufdZ0wV2LNpvkQr9GawQFJ71_cHV3MO" ascii
        $s9 = "dnCNAen3RFXj0X3PuBdcQ7fKjR8mrsRV_D3TQhBY1KMpPxt4kPwKwJm26_-1Qm2nOwxgPf9-jstIyrJFSzs8KWDLZBf8OQLTAIMo" ascii
        $s10 = "rrider6L8mRW1EoOiH2DQgX28M6ARykyUaMLQsohXSvgmcbCtci472dzuNf62f0QWKSpzvUuy6Z-vySOjUJqeoLw4VtZHhu9wlgG" ascii
        $s11 = "9dOts2salzDpNZ4FZFL8fjB0W9z01jvn1v7ZX8YxGq-_bPMpOf6wsb8Uyz4p3wMM6dJcr8ekyLUKlMn4FYxH8ly-XQgrWm5-ptPu" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1204224 and 12 of them
}
