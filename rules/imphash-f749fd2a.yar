rule Sightlines_imphash_f749fd2a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f749fd2a"
        date = "2026-11-10"
        campaign = "imphash-f749fd2a"
        family = ""
        hash = "0020de4bb48418ad6c7e831c587bcab3225ce1798eef12d702789bd7763afc78"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f749fd2a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s3 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s4 = "NSt6thread11_State_implINS_8_InvokerISt5tupleIJZN3Mux11reader_loopERKSt8functionIFvSt10shared_ptrI6S" ascii
        $s5 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s6 = "m.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requested" ascii
        $s7 = "NSt6thread11_State_implINS_8_InvokerISt5tupleIJZ19relay_stream_socketSt10shared_ptrI6StreamEyEUlvE_E" ascii
        $s8 = "*NSt6thread11_State_implINS_8_InvokerISt5tupleIJZL9link_loopiEUlvE_EEEEEE" ascii
        $s9 = "St23_Sp_counted_ptr_inplaceI6StreamSaIvELN9__gnu_cxx12_Lock_policyE2EE" ascii
        $s10 = "*ZL9link_loopiEUlSt10shared_ptrI6StreamEE_" ascii
        $s11 = "ERROR: server/token are empty. Fill them in config.hpp and rebuild," ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
