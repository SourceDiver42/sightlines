rule Sightlines_imphash_a713783f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a713783f"
        date = "2026-11-22"
        campaign = "imphash-a713783f"
        family = ""
        hash = "17c2733268c6797bd250346ebbae01620ae3df646e047cb6741e076e96b654b8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a713783f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "O2queJLVZqiHx2-eKLuMz9lBoTD4AYOT_L1z960b48YlhXm6r9sC_7FVusnKhgfPrjgrCyfHSfaUs4NBh43Jw7hVkNp5CE2qv5PX" ascii
        $s1 = "TwH3F3L3bMBl0B6OgiJSL9FOjN9Bh2yVD4xXEWvK61oEuCiSOb5ER3YD_Jt8PAmKC:\\ProgramData\\hangdog\\iocsucks.cfgZ" ascii
        $s2 = "OwSW34wh7jAqGkVhefmcxHZGr7pjNnusmYmjIOLHox-_vnZvxaKprmlTCExR-aR0gUJCzMt37gX9Gh2hq6bjxRD91HT4I8ooFc-T" ascii
        $s3 = "0kqH__mXg_rCk9jYDBCscLPPStwj9S1T8ghaDS7Pu6B39EtXcBAn5ebpiEOHyR8dvFI8FFWGJQZCFp8USsnkzuZXgt40x4MeBSoz" ascii
        $s4 = "aF3PyV34HWXwfLAGO88dXToKerv0gSx1DCwN0-fSnt6akD4y6wFQhzai9uy-IkH8R5xHhO16iZ1X4ok77S-BBMlbJhzrCUcPQarN" ascii
        $s5 = "PUFuX84NpqGC9BhkvBnzxRzDw2lPsoKS4ShySkYhmmsfb6hHCMz78QUSOFXadRVx7Cml5ENWmAZ1PpGUw_UeT7Zbjk1hoicc3sVc" ascii
        $s6 = "vpsjN7HopRG2hLxqy0whC58nysHEM4pzX4mVK81JlKQc9HABKtEWpFTK4pkMrWLYErK3M1ebrudL5ATgjyKwtODfn-aLD9FO9Zos" ascii
        $s7 = "THm2lpRzKUY7bjSAt9pgw7fcotJVXPls2AZTO1cF4had0AfDCDOLL5j8Wu8QjS-lqe6s7MhKYiyrpRsYEJvZ6uhgKf6jRukSyjkj" ascii
        $s8 = "8gudxTsG_ti3QmMt5XxOdgVEv6eEtVKkVl-HBTCZLeu5AUSnsNh2iCWZDTmjzcs7YxNOliLQxn9YkHWIi40FDMjFwC1GbDuUWU2H" ascii
        $s9 = "if_o-kMk9QaHqqB5ZIGui3mPSh6Ar5asa5eoKIDeb1253wW17LMhxZD2FXzniBKKqLXGZ9g_EL-_WvpLYjvaR75QtM64SoVPJ6cT" ascii
        $s10 = "AYtdn_cQw-I8tKN5ovE-BnbTeLrXsiNaaIUStfh_DU5mIuIZQQ7Bl4_CkPvyg3HLGTbTMdSuzGT9iej2kGJkpG2JJe2Q8AFaJ-5x" ascii
        $s11 = "-YCB3A_3SaRMMFkDn9nyuzsWVexPZPesNGFaRL1gEsEtuEg_C2pIQDoHNZXyE646YfwWdFdxk9MWyeSNgX5Ot9bk-hiOqHrmqAdb" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1248256 and 12 of them
}
