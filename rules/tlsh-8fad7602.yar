rule Sightlines_tlsh_8fad7602_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8fad7602"
        date = "2026-11-23"
        campaign = "tlsh-8fad7602"
        family = ""
        hash = "cc8ba71c1c182ac368a4a62123d4f8813eb3f2c51e91908fcc918fec0f50d874"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8fad7602.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "90368<IKM>@CFHOQTV]ceXZ\\_ahjxwmlprtv\"$&\"$&" wide
        $s1 = "the shortcut.ShowCmd1;3;7The show command for the application window.The following values may be use" ascii
        $s2 = "f the file to be removed.InstallMode1;2;3Installation option, one of iimEnum.ShortcutForeign key int" ascii
        $s3 = "d.WkDirName of property defining location of working directory.DisplayResourceDLLThe Formatted strin" ascii
        $s4 = "omponentIdGuidA string GUID unique to this component, version, and language.Directory_DirectoryRequi" ascii
        $s5 = "ch foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;Language;Identifier;Binar" ascii
        $s6 = "y;UpperCase;LowerCase;Filename;Paths;AnyPath;WildCardFilename;RegPath;CustomSource;Property;Cabinet;" ascii
        $s7 = "_ValidationTableColumnNullableMinValueMaxValueKeyTableKeyColumnCategorySetDescription_SummaryInforma" ascii
        $s8 = "tionPropertyIdNValueIdentifierName of tableName of columnY;NWhether the column is nullableYMinimum v" ascii
        $s9 = " its display.UpperCaseThe name of the Directory that can be configured by the UI. A non-null value w" ascii
        $s10 = "to suppress action.AdminUISequenceAdvtExecuteSequenceAppSearchPropertyThe property associated with a" ascii
        $s11 = "The display name index for the shortcut. This must be a non-negative number.DescriptionResourceDLLDe" ascii
    condition:
        filesize < 1048576 and 12 of them
}
