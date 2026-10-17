rule Sightlines_tlsh_4138e208_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4138e208"
        date = "2026-10-15"
        campaign = "tlsh-4138e208"
        family = ""
        hash = "06ccf95a2ed644d9c2a3834e6a14ec1184b7fff82dd4b42c55957ed1e346f3a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4138e208.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "((FreeBlock->Flags & HEAP_ENTRY_DECOMMITTED) || (ROUND_UP_TO_POWER2(FreeBlock, PAGE_SIZE) == (ULONG_" ascii
        $s1 = "tifiers (RIDs) have been exhausted. Please see http://go.microsoft.com/fwlink/?LinkId=228610 for rec" wide
        $s2 = "CLIENT(ntdll): Found CheckAppHelp = %d for %wZ in ImageFileExecutionOptions" ascii
        $s3 = "*!(CheckedFlags & ~HEAP_CREATE_VALID_MASK)" ascii
        $s4 = "(This->PrivateDynamicallyAllocatedString == NULL) || (This->PrivateDynamicallyAllocatedString->Buffe" ascii
        $s5 = "A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER" wide
        $s6 = "ROUND_UP_TO_POWER2(FreeBlock, PAGE_SIZE) == (ULONG_PTR)FreeBlock" ascii
        $s7 = "his error if the display driver does not support the DXGKMDT_OPM_GET_ACP_AND_CGMSA_SIGNALING and DXG" wide
        $s8 = "An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type." wide
        $s9 = "Init routine %p for DLL \"%wZ\" failed during DLL_PROCESS_ATTACH" ascii
        $s10 = "May not specify Lock parameter with HEAP_NO_SERIALIZE" ascii
        $s11 = "SXS: Assembly directory name stored in assembly information too long (%lu bytes) - ACTIVATION_CONTEX" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3389440 and 12 of them
}
