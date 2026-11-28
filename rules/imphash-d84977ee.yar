rule Sightlines_imphash_d84977ee_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d84977ee"
        date = "2026-11-15"
        campaign = "imphash-d84977ee"
        family = ""
        hash = "823264bc3591735c98585b1f41ea4dc9e8e160ec729ce90f28b28f3e5238a84d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d84977ee.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DebugObject bypass: NtQueryInformationProcess failed, NTSTATUS 0x%lX" ascii
        $s1 = "[JIT] DEBUG: DecryptMethodBodyByRva returned null for RVA 0x%08X" ascii
        $s2 = "[JIT] LdrRegisterDllNotification failed (NTSTATUS=0x%08X)" ascii
        $s3 = "DebugObject bypass: ucmxCreateProcessFromParent failed, NTSTATUS 0x%lX" ascii
        $s4 = "[AMBC] FATAL: Method cache full (size=%u) for RVA 0x%08X" ascii
        $s5 = "Calling K32_WriteProcessMemory(hProcess=%p, remoteAddr=%p, dllSize=%lu)..." ascii
        $s6 = "LoadAssembly: EntryPoint.Invoke_3 failed 0x%08lX" ascii
        $s7 = "[AMBC] HeapAlloc(%u) failed for passthrough RVA 0x%08X" ascii
        $s8 = "Calling K32_VirtualAllocEx(hProcess=%p, size=%lu)..." ascii
        $s9 = "[LdrBypass] Blocked amsi.dll (STATUS_ACCESS_DENIED)" ascii
        $s10 = "[LdrBypass] Hook E9: target+5=%p -> bridge=%p, rel32=%+d" ascii
        $s11 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2020/WindowsSettings\">" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
