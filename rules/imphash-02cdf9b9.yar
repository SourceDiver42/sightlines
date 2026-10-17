rule Sightlines_imphash_02cdf9b9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-02cdf9b9"
        date = "2026-10-15"
        campaign = "imphash-02cdf9b9"
        family = ""
        hash = "4cdb91d0a92775a43ca2dd4b92481b849532359649e40d16e307eb59414cc4b4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-02cdf9b9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s1 = "SizeLimitExhaustedParseIntErrorInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee720" ascii
        $s2 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s3 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
        $s4 = "i1\"AWouldBlockthread name may not contain interior null bytes_______ac68faa20c58cbccd01ee7208bf3b6e9" ascii
        $s5 = "RNG failedWrongAlgorithmInvalidEncodingUnexpectedErrorInvalidComponentPublicKeyIsMissingVersionNotSu" ascii
        $s6 = "ring::signature::ED25519assertion failed: key.len() <= digest_alg.block_len() / 2" ascii
        $s7 = "accept confirmationhrr ech accept confirmationCLIENT_EARLY_TRAFFIC_SECRETCLIENT_HANDSHAKE_TRAFFIC_SE" ascii
        $s8 = "SystemRandomRsaParameterspadding_algmin_bitsNoKeyLogCrlsRequiredRingTLS_NULL_WITH_NULL_NULLTLS_PSK_W" ascii
        $s9 = "ompatibleConfigSniRequiredAlertMessagePayloadEd25519SignerRsaSigningKeyAlertDescriptionAlertLevelEch" ascii
        $s10 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s11 = "'..= | !nullboolcharstri8i16i32i64i128isizeu64u128usizef32f64!..._R__R" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2993152 and 12 of them
}
