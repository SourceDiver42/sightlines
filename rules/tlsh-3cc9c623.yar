rule Sightlines_tlsh_3cc9c623_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3cc9c623"
        date = "2026-11-26"
        campaign = "tlsh-3cc9c623"
        family = ""
        hash = "051e355666d8d242827c7969b70f6da6b7f27aa23fcd5c36fcb0c81bc25a6856"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3cc9c623.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "compiler: cl /Zi /Fdossl_static.pdb /MT /Zl /Gs0 /GF /Gy /W3 /wd4090 /nologo /O2 -DL_ENDIAN -DOPENSS" ascii
        $s1 = "X25519+ML-KEM-768 TLS hybrid implementation" ascii
        $s2 = "Negative big numbers are unsupported for OSSL_PARAM_UNSIGNED_INTEGER" ascii
        $s3 = "assertion failed: !EVP_CIPHER_CTX_get0_cipher(self.as_ptr()).is_null()" ascii
        $s4 = "UserNotice ASN.1 structure found but OID did not matchValid PEM but no BEGIN CERTIFICATE/END CERTIFI" ascii
        $s5 = "cryptography.x509.extensions_CRLREASONFLAGS" ascii
        $s6 = "P-384+ML-KEM-1024 TLS hybrid implementation" ascii
        $s7 = "Valid PEM but no BEGIN PUBLIC KEY/END PUBLIC KEY delimiters. Are you sure this is a public key?Incor" ascii
        $s8 = "P-256+ML-KEM-768 TLS hybrid implementation" ascii
        $s9 = "X448+ML-KEM-1024 TLS hybrid implementation" ascii
        $s10 = "assertion failed: !pctx.is_null()C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b" ascii
        $s11 = "assertion failed: niv >= 0 && niv <= EVP_MAX_IV_LENGTH" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 19870720 and 10 of them
}
