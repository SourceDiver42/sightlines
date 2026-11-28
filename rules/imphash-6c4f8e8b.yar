rule Sightlines_imphash_6c4f8e8b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6c4f8e8b"
        date = "2026-11-21"
        campaign = "imphash-6c4f8e8b"
        family = ""
        hash = "422475e5b4ffc3894c1fa91505307d1b6a6d412949f29a079038be48e3bf101c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-6c4f8e8b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SeuOdoqzBpyb2BmlI8YGXW59MLFVEjQ7iUXa43Gr0TJsbdgXDEZGAYfDeHc6mR_aOIes3Q7wxT8TV1HG_EVwBhijMucjOjjxvKdX" ascii
        $s1 = "UynUfao0CZgoDiPbaQvL9eB_r_TR9_4zumwTBNI_SA3Vsa_2Y82pHB1fQwHQbGjOm1RRW7z7DvJSmI9M7QxkylkwdVWE80qGSqNK" ascii
        $s2 = "KJ8QK4SCvybIZ3_bMDTLBlIfk2boS-2ETJPh8aYAmun0WmbExX5Y9zFuqZA2dCyV8i7UyjUz3g9kZVQdsipKD5q6qUrshNcKKLLZ" ascii
        $s3 = "e0U2uI4KylzKbtVCoV0mZZJdY1Yi7QcfJjnH4aqVP8TFbez3BhIR-J5jSPsi5xtIKjhlPo4wUH8Oa_sef-FwkpmMS8xKFaHEXA M" ascii
        $s4 = "YiOCxHu6DS7CgCDenFj4oY0oVC1FaEtpdfDn_9gAnFIqm8-0j_qk8Ny9VheWzj3ifU5se-4Jip2kPOGQYdWkrDMXbpUg9fBF1hBL" ascii
        $s5 = "cztyUL5Az1qboHECKCWGLwNvfR_aU7UpE7-ibZja4q87B0znr7uf1Za9mzQETNfAJxnLeLVr3W8vXj8AugOvFd7JtTVCMQ6PKqkp" ascii
        $s6 = "hyb8qRn2r0Bez3CL4c4YsovWWtD45zNwt9V60P6-GAwUJiIMlXTqxCpnTukPYmKB8ARcSjttJXX-Om1n7z08MblqPiy64acXrGr1" ascii
        $s7 = "Nk6Am8YW4FaNAUkI7sm5enGvS-PpfIOVnE1QL5rubX3fdrcE6p3Z4K_5Cdr2iG3lksx7qYehEY_LAh0-SpOd0aG-HjmDJBXc6mIH" ascii
        $s8 = "98cdwKPEWT5p6ijj8nYN3-DMjON3a6LQLmRwPw9dDGMfiZaafSLLOkbdRz6xH2j4fh7Ie0e-AVFuwrXv5IzUwb8V_yE8cWvrs3iU" ascii
        $s9 = "j4PyCMLs1t1uoJXttSIgRQAqS7Q_hx8jMopaHhZbjcUrOK9nCJsOvOoDUGFgwa0MHzjfi2llwQ-z9TCe7UBcrIRBwEfIF2jWwggS" ascii
        $s10 = "wB_jKmYpKalv2oyxPcqVI6cJ0rj5qhjOwt91gvbOcwMbR8Dw-T6nHlZQ5SxgMo8isuve0mFGHX7oIDkVu12mfMV5e5NyZueJ6IZF" ascii
        $s11 = "YInu9_tIeh-VOLHaYTZ1dJmgoQH5si8X_3PxFQmUtLK1XT01qxQiuqb8IJ19D6LtCohATtRSSMO1B4hPFdd5UfLwj1cWVf7yMn30" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1266688 and 12 of them
}
