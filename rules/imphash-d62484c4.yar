rule Sightlines_imphash_d62484c4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d62484c4"
        date = "2026-11-15"
        campaign = "imphash-d62484c4"
        family = ""
        hash = "038ac9a9e3ea740a0ab1f415f57af0321701013e1bee625ddb7ec22872591706"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d62484c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Incompatible object argument for invokespecial" ascii
        $s1 = "Accessing value from uninitialized register pair %d/%d" ascii
        $s2 = "Quick instructions shouldn't appear yet." ascii
        $s3 = "Expecting to find array of doubles on stack" ascii
        $s4 = "Fourth operand byte of invokeinterface must be zero" ascii
        $s5 = "Accessing value from uninitialized register %d" ascii
        $s6 = "invokedynamic bytecode is not supported in this class file version" ascii
        $s7 = "Expecting to find object/array on stack" ascii
        $s8 = "Expecting to find object, array, or int on stack" ascii
        $s9 = "Expecting to find array of bytes or Booleans on stack" ascii
        $s10 = "Incompatible object argument for function call" ascii
        $s11 = "Illegal creation of multi-dimensional array" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
