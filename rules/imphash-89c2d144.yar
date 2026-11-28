rule Sightlines_imphash_89c2d144_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-89c2d144"
        date = "2026-11-21"
        campaign = "imphash-89c2d144"
        family = ""
        hash = "4712017f3da550880d474c47c033ad0ca1574364fd302881e75a0f4761cb911a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-89c2d144.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PLux_l8FZ3W2B-Yr2NRr4clmJxY2u1N_uQrojqKIEpPZ1YdJBMw-CwuDVkD2nTts_eEwvfLvGTh8gUkIg0RGKWG6z9ktF7arijI" ascii
        $s1 = "LcNbZ6zgLwzjANIcKtREMZSe3tKTbBpBKrmNUSj0dgQ3DggJyO-dqfz7Y_x-V3-pWvfOrkKo4Z8JFasuYD_bw-nJGsX6Hnyb9g3u" ascii
        $s2 = "46aW9FWiRSOtAC1F4sNz-IBesPZl67Gbc58_gV97siMcJ_awSoEHL6dI30lMfxqBP39BpSryWT_M_Kj89UJ4BakAQbgmQEUSfI3W" ascii
        $s3 = "UFKT27uO-SCuBa0sGEI6OExchRms9XxiRGt1djaymyQivr6DK2_qO7J6-0P_PzHWoSjRh6L3Fn9c5gpkMO4Nvt4NyiOKOVoBsioS" ascii
        $s4 = "P0uSIaPFCtFppu6y83SLDRBYhR2juGOoEFU2SV_NZP08-cwrYWf2ho7tA3Ga1M8n1-z0O5jJsUKj6cyHixZd7DH3NX43Characte" ascii
        $s5 = "HmhW9A7iFRdtZuKTa-Xy05LrH9StFfXe7q6KKgwFGVW5x1pyBoczREGfFzhhs1D9q2YVTJwfsV_1IM7fX3Lzx_SsbfCyk6Hj0SPD" ascii
        $s6 = "_cAiJuSSJgKXE6Ok12Pv15f1tembI6M_7ncbWgr78Ag6tu6lwZfxj1s--IXFRIzFyU0zpCXRJ-Kwol3OhwuHhYD34d_kD0RS4pAX" ascii
        $s7 = "mmlQZU3ggn9ncLTfFcpROn4mtUqGmaDXpAMa3kdv1KHaFcfMp9hQCl-A5E1Doko6YKpjwORyT0OeS3rpzuz7BLCA48wv6Wd8xna3" ascii
        $s8 = "coE7pd8mp9_8CjScHfqND7JPBPTZwUw8XyfvSBzowojW-eHCukETXFpRYgxOtrd3lzaYNg2sVamaFWbo003m_px6utgrYSki18CS" ascii
        $s9 = "of8FA_2eKwNGjN3fhuSWJ0q7j8QQQf8roBHYJNdWBFeYcLAPDX6aFyngswCpXRhvXd_eJIQ4JC3af_-_oLu5BqkZ34xntvEEni-U" ascii
        $s10 = "TuD7RESNEYyN04V-k9E-uc3pBfWJOIt4qLMxXPDOohG7yDC-dyJiCrrTlOYiQOrc0nSbl_etAJlU7mM9gj-Z1adiQ7SAOfalse_q" ascii
        $s11 = "_N-U2DZrEj0Sd33aVRdtmi_KnKklrqxwg3gCRbCT9eA51UjSYHP1L8FQmFgXYszk5Au1o5VyIcA_I1Bqa8VkeY5Q__3LJ7mqnoTH" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1256448 and 12 of them
}
