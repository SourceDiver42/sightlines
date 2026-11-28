rule Sightlines_imphash_d27dd56f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d27dd56f"
        date = "2026-11-15"
        campaign = "imphash-d27dd56f"
        family = ""
        hash = "4849d26d0b15896de19d5571fa701f321877c5e75360e8ff8950103ea7513bcb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d27dd56f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "jdwp usage: java -agentlib:jdwp=[help]|[<option>=<value>, ...]" ascii
        $s1 = "handleFramePopEvent: starting singlestep, depth==OUT && fromDepth > afterPopDepth (%d>%d)" ascii
        $s2 = "JDWP Unable to get JNI 1.2 environment, jvm->GetEnv() return code = %d" ascii
        $s3 = "DEBUGGING: JDWP pause for PID %d, THREAD %d (0x%x)" ascii
        $s4 = "handleFramePopEvent: BEGIN fromDepth=%d, currentDepth=%d" ascii
        $s5 = "stepControl_handleStep: NotifyFramePop (fromDepth=%d currentDepth=%d)" ascii
        $s6 = "JDWP unable to dispose of JVMTI environment: %s(%d)" ascii
        $s7 = "    java -agentlib:jdwp=transport=dt_socket,address=localhost:8000 ..." ascii
        $s8 = "JDWP unable to configure initial JVMTI event %s: %s(%d)" ascii
        $s9 = "Received jdwpPacket with flags != 0x%d (actual=0x%x) when a jdwpCmdPacket was expected." ascii
        $s10 = "s\\src\\jdk.jdwp.agent\\share\\native\\libjdwp\\ThreadGroupReferenceImpl.c" ascii
        $s11 = "handleFramePopEvent: starting singlestep, have methodEnter handler && depth==INTO && fromDepth >= af" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
