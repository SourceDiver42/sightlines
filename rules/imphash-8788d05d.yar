rule Sightlines_imphash_8788d05d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8788d05d"
        date = "2026-11-12"
        campaign = "imphash-8788d05d"
        family = ""
        hash = "063958a8e090e4a767b8458119535efa575fc3acd61168f8f6773d886c11f82b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8788d05d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "g_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP" ascii
        $s1 = "ig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NO" ascii
        $s2 = "Config_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcde" ascii
        $s3 = "onfig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef" ascii
        $s4 = "_Config_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcd" ascii
        $s5 = "0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_P" ascii
        $s6 = "123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_PA" ascii
        $s7 = "fig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_N" ascii
        $s8 = "23456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_PAD" ascii
        $s9 = "nfig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_" ascii
        $s10 = "a_Config_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abc" ascii
        $s11 = "_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 29220096 and 12 of them
}
