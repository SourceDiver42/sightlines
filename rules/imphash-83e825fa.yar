rule Sightlines_imphash_83e825fa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-83e825fa"
        date = "2026-11-26"
        campaign = "imphash-83e825fa"
        family = ""
        hash = "38507ea1ba1a249ad760f2add4fd9586bc526a093d9436490201590ea7904ac6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-83e825fa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "-ijZHJG1tqFdP5I9yxVqxn54Xz6yBKlddQwD7GhOyXMcUW9EjeqXpPX3DaTm1RsuGICh_pbdpE9lRQYNhZn2lAcSkE_RgakKFiom" ascii
        $s1 = "c1I211naPzdTrCU4IZvW6T2Xeu0-XNwpTNOXm7Dd9kErZLG28j_D8r_KOlCoEqroPHdsrnRymwUeAoPwb3jNch5tI7JxilfmiyFp" ascii
        $s2 = "2FualnpmrDCELhTtBheYi3HisbkGiR0fsZDt3JGJNVs5GW1rcqIUdyHzwb30IWtRyjLyVASgi6t1yzKdIzhwosMsQ89CPkaA1D-X" ascii
        $s3 = "OoAQQ7t4mUJF6fwjDIwt1C7i1R0V6HxvJTMp3Eny07pLEYuSgnYzsoQ5V39lCcsn1hd2dLU_IkuWFnIvNYiZ5QsW1fqU5bWAzYGe" ascii
        $s4 = " prefix40Za6Upqn__WQyVtRPY-LVDm8uX0PoAXla1QxSLV6IgpTkcHF0LNTYOtGMs_KtbVdumxzcsOFi44W0NFmhZ8gZ6HI6b19" ascii
        $s5 = "GV35q-5tnycyGtvj5WXTisa7BMeHUQbou9SOEnSFrTxZO-IkOCUjk_Ft16L0mSo4Fei8KEqMRA2rl_-lFS3sjvI3eMePkENX7bG8" ascii
        $s6 = "4okU09QNrzMlMApjfAY7P-kULuDP7R108ijvza-kW9MoXONW6fKL1HcfkJRFEjTbQeea6Ns-bvwSOEg2Nm2JxZqmA2DlVtQ62uxL" ascii
        $s7 = "asYEFedKLjBeDRnmTButlMUoFemdzQNEYAkUWnfT3IEeXxyuKwVPvJ8iu88Cc_-mbekScB058HnGxjlE3tHok3V_U5IUX2i47zSN" ascii
        $s8 = "ErQkufyYXnQBJ4ZZ9_cx5ddxRySFJX0pWv3H9lbLRN1XLE_Apa8HsishQnAW6Bk789xygYo7tw4JP2f6TFSnOKRaFpoL7Viy3EqE" ascii
        $s9 = "WIeLlFh7vLEZB7fKpquRh08w3guOZY4mMi0iUCHx9tpq38qpNxulG92_uq-rgQnC6goGFUovEeFfIEj4zTYJhSERanoQLHhwkId7" ascii
        $s10 = "cGOt6j3MDrxRBrXp2CqhRHfx9-X-eafnt_HnbW9z70aw5AHXVJocDFP4gCvyVEZUqgGhz16gGbsfVSXl_hb_jgaRL7j5Wy1KV2Fc" ascii
        $s11 = "QNynR9trSJjw5MS5WTbZ6H-Ad5URyy0n0UnrMzce5VBw3NvRiRtPTei_VclmfxSI0OC9UCoyeBSEgbFKDVcjhdkTuXXy2NJr_v7u" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1411072 and 12 of them
}
