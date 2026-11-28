rule Sightlines_imphash_c18edf58_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c18edf58"
        date = "2026-11-06"
        campaign = "imphash-c18edf58"
        family = ""
        hash = "22e35ec77593e68542f358359946a5dd911658234fb967f17145cab92eb0b6e4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c18edf58.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dq9.nvoMrTvEeIJ08ybINap2hyBZf2xPPwlSQcj3NE71WhMSwuzSIS-zD-EQzeX.aRBYV5p8-3gBOcFF51_G7KN364W6SAHkqVAh" ascii
        $s1 = "KENWutcszNK14Pl2XGz-9C-.v_-Huw38jEfVoZsFURRs9_ja1giIpjGQwID3OFWIMxO5uC4yhMegD2qS69H.iJgik8h7LE084fj-" ascii
        $s2 = "Bon1rBjD5vcAStTppdggxT-eowZWU6d2Zd7zDeHXigR.q8VkcIE4tL6kVzCYhC9tx535R07ujL2s5BNw-Sbur5I_C3OZj0PZkyXS" ascii
        $s3 = "LIjmAAEDdr3aPwkelQOg9SmyJJaXN_iFCvXxR1xjq8YetOPis09WSdftErV4Mxp2QO7omSXonJLhCk14-fcXFs_md3U-DozepkNM" ascii
        $s4 = "uCIsg0UeJbTH96OiyOLJjvL.kitZ44XZ5mnT9CcWZ37nGIsRW6KqivoUbqaP9ZgaDFNBrT9dfH59Ne-Sf8y.pS-Zmf_tmYB4UQRB" ascii
        $s5 = "Jj8-CpmseDtgcHuC5L1VHGLk5x6wd2kEqsJDJTkKWZE.UM0S3fXN9sTBYOLYMBuexFw1On_M-WCW5wMbv85UdPIcTuAYc221crx7" ascii
        $s6 = "B75TWbGsKicOXWnp3vujnic.y6OBStx3e0RQhILmUm1vdu7nKfFcbI3gRt9Sr-QXi5JTzPkpf4u2i7hfGDm.wtXwqUrK7dIwZ1Az" ascii
        $s7 = "sVEswQPzTU9gJui9qexpuZobLDWFCkG19Kc7Fd0ifMp8196W90CWY8Vp_gQJbe52YL9ONHMU945PHmt5qRMzUJB0PnohnmhjAL4_" ascii
        $s8 = "NTgt-IVXijRsLYuoG2V_uuwSgUilCYWD4ROVcsKaCHuQCVPMUOXCB7tDBAOQ3UR-oVKhqpJhgbnNZl-rV7RFWaXr5Sf6vPlzEp0s" ascii
        $s9 = "1uknmi1baxy-QiJCskt6nDY5dgQmGC9PRrGgW-Dc-UOJc1mNZGKAk81V9Fow67AJLdgNE-E4ebK-W5qIXpMO6SZPnJdakly8jfAX" ascii
        $s10 = "HVGwYOEc6eueib2Jk1Bo0pS.VF0clTopdAUnJUXYe1DahGKuFZhfMrnBrtrCLPavK9YX-60kcEqa6Za7PHH.7Y5tvHxVi8_6g059" ascii
        $s11 = "ym9v6xkNPapw2tVUo6dYPYZajsEgfFQ19dqkI4RMxaH.QbZN9j8g0f_RNG75G_IWZudk0Ud4M0wQ6KjLhX8fhG7VZgSnATF15mwc" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1245184 and 12 of them
}
