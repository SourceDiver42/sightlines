rule Sightlines_imphash_bafe325f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-bafe325f"
        date = "2026-11-05"
        campaign = "imphash-bafe325f"
        family = ""
        hash = "37e5e96171a38ed99bba0d59dda7d99049d024ea5daf48a6a1b228e57d4a92b7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-bafe325f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " <?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>  <assembly xmlns=\"urn:schemas-microsoft-com" ascii
        $s1 = "PyUnicode_TransformDecimalAndSpaceToASCII" ascii
        $s2 = "PyArg_VaParseTupleAndKeywordsFast_SizeT" ascii
        $s3 = "PyErr_SetExcFromWindowsErrWithUnicodeFilename" ascii
        $s4 = "PyErr_SetFromWindowsErrWithUnicodeFilename" ascii
        $s5 = "PyEval_GetCoroutineOriginTrackingDepth" ascii
        $s6 = "PyEval_SetCoroutineOriginTrackingDepth" ascii
        $s7 = "called `Option::unwrap()` on a `None` value" ascii
        $s8 = "panic in a function that cannot unwind00010203040506070809101112131415161718192021222324252627282930" ascii
        $s9 = "PyType_GetTextSignatureFromInternalDoc" ascii
        $s10 = "PyArg_ParseTupleAndKeywordsFast_SizeT" ascii
        $s11 = "n failed: edge.height == self.height - 1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 19946496 and 12 of them
}
