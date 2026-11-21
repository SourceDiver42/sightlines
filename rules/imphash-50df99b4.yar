rule Sightlines_imphash_50df99b4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-50df99b4"
        date = "2026-11-14"
        campaign = "imphash-50df99b4"
        family = ""
        hash = "28024da475ae43927883d6a3de1a360cf90e9439a5cc43c00cfd4a24f57bbe21"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-50df99b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "vYN1g5MFy6VA8SDam8ni-7O2hV1WwBKULpOJoCWTfa2UH6hCGPp3Yx-DbJnI6DyTwvOskuHooID-zt05XgSJPErpLaR7kkN4MjI" ascii
        $s1 = "gOny7VIVEoL7Mqq4gKzy3xL1vsSDJWu.OmmUpZdtKi40WCTiRFEjfwOwyBf6uaDhMqs6v._3703J1d8Uu_QoAeT-1S0ePvr9wjQz" ascii
        $s2 = "h2E6b0MHJvHStVsMOWDKOA68H.GpyXUAavLzJrYL5EynYVqf9AATEPSrHR-eaFt.QU_y2RQ2kdxSih7NPf-P8oWslUSxGBuvwXI2" ascii
        $s3 = "KtzVq0VpsYupVQ5_Rr3sgJe7Md_nVCBibrhxYb82NJ9Ea4oR-wMmfD1X-OlBCJ8Y-mBt_BAGQnz6C8JvA2mKnjWecK02KThPoSDg" ascii
        $s4 = "7lTC98OPgAqsjfIk0kqMfz8lGN1vydU27oEmQpxWM1RnBOiA0ONfVJjtxwcBZUM6i1QV6nB3LERKo_cL8SRwnHvDbLaqV1Ew7hs6" ascii
        $s5 = "wB7AOzXeb.S0VVgoxizAzQ7K3HC7sY-o6foaP3KLFnpjT7A.2WGgJ-93hpF341tay9VhMm_ntRfSE1XqFZrXr.n4YRkTOGx5ZRn9" ascii
        $s6 = "ntry,Lr9jwfUrbAVlazsPZki6ceEe1U73fAYhtCw33.t3aFpv6k41vBglXg3x1SnKpl7blGHBBkCbpXfZ7VuB96_cozRTJQd2Ma5" ascii
        $s7 = "71FDCBRb4Lk4drBBB1cGIVAe87gSa.hgK7BSo22u_jhva2yxw6IrLQANXlFlan4WK__.p9bGVsA9fkSpYOR5bPmhXicmPWjcUMum" ascii
        $s8 = "XW-.LX3C23lOTHIPcVZtQCrYvWILt8YgmV2ubBBhU.yIN4wdUpDVPqkE4QlArOdz9yNp8Nn9rfGAeKU.cC11an7Ltz7eRGx71RYY" ascii
        $s9 = "pYpCr7mAjWhzih2h-Iu_FCSKgD4xsE2.Jntx05JtlP41_68q-g5-LpalMqRtmvZtY6hVL.Jsb3wO6MaJg9JBc1nOHkgycniFhegc" ascii
        $s10 = "dXhJu--roSNUI-LQ70llozIEcCZPDzUSyf6br.klJaYpq88v5MjDNHE4DTORIkZ9sZPINXsVqBV.pqYARn00ERvBy9p_7t0ybegR" ascii
        $s11 = "pujLLkjCO3AraYXRgvftRJK0PEAC4NgbLzJqYy5ogEJf8z5PUMDKsBV10jxIwuW6CkhGvJh2RbWOpn9bSX8UaJZtQP3GTh6rytMr" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1215488 and 12 of them
}
