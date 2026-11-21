rule Sightlines_imphash_2953f798_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2953f798"
        date = "2026-11-17"
        campaign = "imphash-2953f798"
        family = ""
        hash = "286d73c0d9f9ade99dc679ef226e9388b535af7a3ca224f8244c6af065ec1e95"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2953f798.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "BjLKoL.ps_cMSyfz9jLUU321ngr8s49MPhdAvh67HN6K5VrGDEVsui8IJn.fbNnzyUkQgjXJVMxas0PWYwZfcRv2lZ1efRIIOFrq" ascii
        $s1 = "5p-09MrV41CpgiuSUKk9uWNe6lbg3F-JCAiHjUgAjuzZ7QjfBs.1MvyqDea3P_O6d-1Ts4xQbPE7LWZWbpMnS2_NARaO2mwKijRd" ascii
        $s2 = " onH-xo0KStTUc2nVDwuZdJN4bwzrL0753EW1GUNTB1NsXG_bZfbERD64aIQsMDpiBhRypzzWOqWHoqD4XCPUC_QnkQ00hei6Myd" ascii
        $s3 = "fNiPJcTnAMyZePU95k4Jhp1kbLQ3su-3aC7RVrncNGFvT6wOg0Gsvsn4XRrAIYxBAg1Z_epOCZ2xcB3_.GzlTytsJqYZCTXmE63C" ascii
        $s4 = "_A2BrQlvCgdPEF12_fy76D3NvelB1kjM797uro6eVLqQriKjIeNBQLK8YQFu0RxplEESC-q_PR5z_sBdFWHXqMZqhaTHt-WSHvwO" ascii
        $s5 = "ezOuEnrnA3XWMyyz__RTNVMUurovaE.v7U-5kVaxSRW1XQJIwN6gdAGm_SM9ZlhtvKrDskyNAPjovuatf1jcTUZs29aqK1E1ifHJ" ascii
        $s6 = "h streamsHcMN9Tv_eYL9JIP0iOOVUnF6hG3cpuhIysfyxzhkfuB8yECVRFbnRLJaN93QAzQQe-wZwCgDpKbZn7YIxvw1z2y3FQv" ascii
        $s7 = "3Cxf-bzdUMgs4RsjKL8ZBDcIQLLGNAV9KrMLvZCv0_b2NQqh67B2BEeFbpADU7oLtwD4w0QXEPanDu7g-PVJ4lIetamper proof" ascii
        $s8 = "Q-wlLnaH9z.5fCm0KZPbg-sgU8yaejph2GaoGux1WrwBWnn1Vb1EOKaMzFK4CN.UNa8Dq0lQE5dJyi3kA72aB8dx9erK9D85Pw5t" ascii
        $s9 = "jBQONRY3tPAn9hrHDRP58fqa0JSSc4RK998GmvkoURV021c1dq9rCTpzV9k5YXBvJ10vtAoFYqib30yMLlpOLNSUXuE0067i1FGW" ascii
        $s10 = "_EnrmUYnEtvhOIlgpbKR-uWOtbipHDPTuad0CdX1cc.kUi5aTGzSAUBdruDYzGPivlKT3h6X9aWCwhMSNrbQHxCAS6PmL3.OLl7y" ascii
        $s11 = "gtOVLDRPSSKrq5QJgqxFK6oxjm309yRbndypkPMMctFHeFO0ct4uyykaTViwCJusLzJASriwU7htwsGEPsNVUoX31zSADq629OAa" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1223680 and 12 of them
}
