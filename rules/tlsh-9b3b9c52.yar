rule Sightlines_tlsh_9b3b9c52_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9b3b9c52"
        date = "2026-11-18"
        campaign = "tlsh-9b3b9c52"
        family = ""
        hash = "0c0a66505093b6a4bb3475f716bd3d9552095776f6a124709c13b3f9552c7d99"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9b3b9c52.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad value for PYTHON_FROZEN_MODULES (expected \"on\" or \"off\")" ascii
        $s1 = "PYTHON_FROZEN_MODULES: whether to use frozen modules; the default is \"on\"" ascii
        $s2 = "sys._enablelegacywindowsfsencoding() is deprecated and will be removed in Python 3.16. Use PYTHONLEG" ascii
        $s3 = "SF_SYNTHETIC: mask of read-only synthetic flags" ascii
        $s4 = "new_config(name='isolated', /, **overrides) -> type.SimpleNamespace" ascii
        $s5 = "PYTHON_CPU_COUNT: override the return value of os.cpu_count() (-X cpu_count)" ascii
        $s6 = "UF_TRACKED: used for dealing with document IDs" ascii
        $s7 = "PyImport_ExecCodeModuleWithFilenames() in the C API." ascii
        $s8 = "Equivalent to chmod(path, mode, follow_symlinks=False).\"" ascii
        $s9 = "PyImport_ImportModuleNoBlock() is deprecated and scheduled for removal in Python 3.15. Use PyImport_" ascii
        $s10 = "interrupt_main($module, signum=signal.SIGINT, /)" ascii
        $s11 = "Exception ignored in PyObject_HasAttr(); consider using PyObject_HasAttrWithError(), PyObject_GetOpt" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12264896 and 12 of them
}
