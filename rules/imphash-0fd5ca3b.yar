rule Sightlines_imphash_0fd5ca3b_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-0fd5ca3b"
        date = "2026-11-24"
        campaign = "imphash-0fd5ca3b"
        family = "valleyrat"
        hash = "3b1a00c35e9bc9171905ffcbc48708d7d325ecaaf969cd581ed5f707c6ed3576"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-0fd5ca3b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/schemas.microsoft.com/SMI/2020/WindowsSettings\"><heapType>SegmentHeap</heapType></asmv3:windowsSett" ascii
        $s1 = "</requestedPrivileges></security></trustInfo><asmv3:application><asmv3:windowsSettings xmlns=\"http:/" ascii
        $s2 = "es><requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel>" ascii
        $s3 = "Copyright (C) 2022-2026 NovaTech Labs" wide
        $s4 = "ings></asmv3:application></assembly>" ascii
        $s5 = "Remote File Synchronization Client" wide
        $s6 = "FileSync Sync Utility" wide
        $s7 = "FileSyncClient" wide
        $s8 = "!Win32 .EXE." ascii
        $s9 = "OpenServiceW" ascii
        $s10 = "FileSync.exe" wide
        $s11 = ".MPRESS2H" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9154560 and 12 of them
}
