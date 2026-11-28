rule Sightlines_imphash_584dc0de_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-584dc0de"
        date = "2026-11-23"
        campaign = "imphash-584dc0de"
        family = ""
        hash = "0cf24caf5d829ad01fa74693f734907179831e3e1ee588faa5410ae05f9781ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-584dc0de.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "YVXxJ2mKQ4k8S38AjhOFi3NixdvwwytPbPe8KTQf0qKM-1lqXdUMsgCk2QrLdnghYMfM9AREGOplobB-jx7Gj5hfFTHXaB_DAcvo" ascii
        $s1 = "T-vdJLrkvKO4O_fqcXSdy8WNzc7ImCp8zS4_9XWzl8nU1Dg6cCyR-xWefRxwb0V32-BnuPdLdHphqPZtdSTZnQXRoj3KmrV1tsGY" ascii
        $s2 = "KJktw6U-pjvH9-lVIXVrhPmSy9m_xL9dGZUBRY-4UMP_EITKWpM7XCabWFTJcOqTlH9WqXei5S6vAZHhE4qPTlong name offse" ascii
        $s3 = "aTxHZmiSjuAOvyF0GteVdXQh2F2UKD-X1wEyUNp-MFZkgtf-59rVufyNXD3OKliWJSA4DVsB8jWbvf14QDJkC91UIjcXI0PgWvoJ" ascii
        $s4 = "0YwGt_WRPsgr6aXp0xFEmQwoo1ioWneMce2kUdUohqiOKMshvYWBJCAJat5a5vVY53iNvDvcj5YICP-J8yVy4QW4llnzz8QnduPT" ascii
        $s5 = "0LOShX-lx-u9k4CrrdHM9fkKTAhWy3D3GnLM21iep9Sbk4z_cygyxqAX9UB3bfmAsWiQsnGF7MjbRKgViO8S8EIT5iD1DTt-faOm" ascii
        $s6 = "4yTJNg8SRMWtWbDef3qqY_E9Oreduction list item typeD_QhvsFABaiLMUv3rnYmlji02l5YmwGMR6RINTxpJEnzXVpEMG7" ascii
        $s7 = "genGUuw1TfpmbujG7YXzsJ48ZSRNWFeEAp8_2SOhNCH9-Hu-x1al-s7mzFuJM0ZGdZ3j3bAQE0Rc7vahrQMjYPu6422q1PAIaHPX" ascii
        $s8 = "X_nypRWzlYQ3JFIll1Gg6nqZUsAewi-rcDDKkj4ft4wqAx7BmVRE2NU2w3H4dEqd6-aUTKEZlAdf4JXoLQst5-DLKlVd2MbTrud1" ascii
        $s9 = "PFGO0S8axz8jKZbFodG1v0pgEX_I2-rpCVieYKyDk8AuDpVt6v0HN7ozVRm0N2wVv9LoW0szdENJ1hoeyWDUWtwmucrSHMuIVtTM" ascii
        $s10 = "ShgMEcuOH0Kbqx_gNNELDE7jkxvVhhgLoUR_9sY6-XIM4hA_h76kCtaySrWMtLqn7zCm_7XFpWHtbkcJ18CDsJBPeh70d8QjYm3z" ascii
        $s11 = "ath when openinganFygkqEVemRgIvd2JYovVweEJL4mc6Io0z8jtVFbUovvZdDBufdA3WBZoQ5X7t3900rwnLqP5Cfu-mO7KSW" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1269760 and 12 of them
}
