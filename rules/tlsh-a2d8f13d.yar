rule Sightlines_tlsh_a2d8f13d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a2d8f13d"
        date = "2026-11-15"
        campaign = "tlsh-a2d8f13d"
        family = ""
        hash = "39227ebd4b73044025bb0fc416d11b6d63aad86b9b0a34de68b6224ac8d24fca"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a2d8f13d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(Ljava/lang/String;[Ljavax/sound/sampled/Control;)V" ascii
        $s1 = "Java_com_sun_media_sound_PortMixer_nControlGetIntValue" ascii
        $s2 = "Java_com_sun_media_sound_PortMixer_nControlSetIntValue" ascii
        $s3 = "Java_com_sun_media_sound_PortMixer_nGetPortType" ascii
        $s4 = "Java_com_sun_media_sound_PortMixer_nControlGetFloatValue" ascii
        $s5 = "Java_com_sun_media_sound_PortMixer_nControlSetFloatValue" ascii
        $s6 = "Java_com_sun_media_sound_DirectAudioDevice_nGetBufferSize" ascii
        $s7 = "Java_com_sun_media_sound_PortMixerProvider_nNewPortMixerInfo" ascii
        $s8 = "Java_com_sun_media_sound_PortMixerProvider_nGetNumDevices" ascii
        $s9 = "Java_com_sun_media_sound_DirectAudioDevice_nIsStillDraining" ascii
        $s10 = "Java_com_sun_media_sound_MidiOutDevice_nSendShortMessage" ascii
        $s11 = "Java_com_sun_media_sound_DirectAudioDeviceProvider_nNewDirectAudioDeviceInfo" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
