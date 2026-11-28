rule Sightlines_imphash_2113206f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2113206f"
        date = "2026-11-26"
        campaign = "imphash-2113206f"
        family = ""
        hash = "45bfde87b24651a7d3d67a0939100b44ca54b9916f0cea3a93f60bc66b010026"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2113206f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "kCajZJSFFdCQ_CVYPMEdG8xB6bd0lT8X3aAUT6479mupaM5VOnQ3UczsTeBtvgfN4IvLNxafdhXSgwOfZ_3iHr-EouaxIItFcPJK" ascii
        $s1 = "V9pow3jehlsbxRB9RSnvumwgGfP6tlDJ-AKA7M0Rk7rjcIFClUZFIe3aw7yLHQonovhg6TwgAiw-1QZymWf4hbq5Js0DGa8hNx60" ascii
        $s2 = "zwItyyLe0Oyp8VcLbiHg9A4qCcf-sCHmJQWqB4BhisfvI_AN3PpkZe0bxC:\\Program Files (x86)\\MySQL\\aioppuens.pdf" ascii
        $s3 = "pd_ymSou8rzCylKsjZB7EI1wIwXdbDu2toqv3EMi_FDjoWB7XQN84qry2XS-v9zX_.gaVx4m5pI4UPefRh7e5P7-Mn8kDQVGXVMj" ascii
        $s4 = "1Gz3NiWC8phAjqkaXLnJxGxcHfTYnQnIZCJyLwk12Knqvs_pDU2EuOlS0JRrVtB0NivtBw0zULz-4fQXcWpI6VQr3UBfup much " ascii
        $s5 = "WdHSaWkAw_QZ6ITn47l_8b-zubvMiWfQ9WA_zEnUw29GEnBOSDOU3Ko-ak3sJxfjGWRGNKWJThElgoyUCJ0NhXcfmr5kgPj8_-f6" ascii
        $s6 = "FheKTN7RQgCBudXQMo6fE5wmKH6H11dhXEHt7HqgBCWV23XxQBnjouCzqqA8UL_QJGT2s1SLri8SqOZvDuMAH1cmARwWuiI4kDlh" ascii
        $s7 = "RaOlF7zUChnk81sMYrA0uv6QNxRWEaMGgTcqs3ldHMYFHbnkwSoNk-ZNagBLZ6JWtXAhLLmvWl5ROrvHSW1ylc9JsAnfNpVwu70m" ascii
        $s8 = "85heVm3ikYRFGMYBfn-StqpnbsiIzV82dNp41LwFIXH-jWWKCfkHG6HcGrCzDWzf1tDvQe6Erx01hK9WhLdJKbUXy4qKCEoVrfI2" ascii
        $s9 = "ROowxmXNyAQud1GKwi_n5tx6eky2XtT4gIZO3CNI0o0SeovbrAmKao-gDxB-MczQ63pVVE0wFmsUpli-a-rADZUaI365e_V_J8ME" ascii
        $s10 = "6wGvflaRCDcl7QGaZ1bT8F48yIl9yyO2KzAP-jWCw1xalrMxmZWN3YwNeI-eMfMqIDgkBAFdbLzEs7GgS3OumnnzqmbjWuZ7OhGt" ascii
        $s11 = "AmjIOoW0H4j-s3-awr-amkKmM6Iir4AUyCO8SljrfsWwByexvFbMShOvTu3i7EyetqSARkLvGbPihrvp5_YjF3BZIxty1DJnkyXF" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1442816 and 12 of them
}
