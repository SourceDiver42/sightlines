rule Sightlines_imphash_ed587ce8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ed587ce8"
        date = "2026-11-14"
        campaign = "imphash-ed587ce8"
        family = ""
        hash = "058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ed587ce8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths" wide
        $s1 = ".?AV?$_Binder@U_Unforced@std@@A6AXIGABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@0@Z" ascii
        $s2 = ".P6A?AV?$unordered_map@V?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@V12@U?$hash@" ascii
        $s3 = ".?AV?$_Binder@U_Unforced@std@@A6AHABV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@2@0A" ascii
        $s4 = ".?AV?$typeid_wrapper@V?$deadline_timer_service@U?$chrono_time_traits@Usteady_clock@chrono@std@@U?$wa" ascii
        $s5 = "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs" wide
        $s6 = ".?AVstl_condition_variable_win7@details@Concurrency@@" ascii
        $s7 = "Unknown ReparseTag in boost::filesystem::read_symlink" ascii
        $s8 = ".?AV?$basic_executor_type@V?$allocator@X@std@@$03@io_context@asio@boost@@" ascii
        $s9 = ".?AVCException@NDecoder@NImplode@NCompress@@" ascii
        $s10 = ".?AVstl_condition_variable_vista@details@Concurrency@@" ascii
        $s11 = ".?AV?$basic_executor_type@V?$allocator@X@std@@$0A@@io_context@asio@boost@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7670784 and 12 of them
}
