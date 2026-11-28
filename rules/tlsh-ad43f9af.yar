rule Sightlines_tlsh_ad43f9af_phantomstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ad43f9af"
        date = "2026-11-14"
        campaign = "tlsh-ad43f9af"
        family = "phantomstealer"
        hash = "0dcfe51d2521e52a469f5cec6b42bc8e7e37b41df993cce7d739ff3fd248d8b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ad43f9af.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\SOFTWARE\\Oracle\\VirtualBox Guest Additions" wide
        $s1 = "python311.PyMarshal_ReadObjectFromString" ascii
        $s2 = "\\Registry\\Machine\\SOFTWARE\\VMware, Inc.\\VMware Tools" wide
        $s3 = "python311.PyErr_SetExcFromWindowsErrWithFilenameObjects" ascii
        $s4 = "See the Format Specification Mini-Language section of help('FORMATTING') for" ascii
        $s5 = "python311._PyArg_VaParseTupleAndKeywords_SizeT" ascii
        $s6 = "python311.Py_HasFileSystemDefaultEncoding" ascii
        $s7 = "PyType_HasFeature(Py_TYPE(((PyObject*)((op)))), (1UL << 28))" ascii
        $s8 = "PyType_HasFeature(Py_TYPE(((PyObject*)((op)))), (1UL << 29))" ascii
        $s9 = "PyUnicode_FromStringAndSize(NULL, size) is deprecated; use PyUnicode_New() instead" ascii
        $s10 = "_read_null(): read from NULL, raise a SIGSEGV or SIGBUS signal depending on the platform" ascii
        $s11 = "python311.PyImport_ExecCodeModuleWithPathnames" ascii
    condition:
        filesize < 24143872 and 12 of them
}
