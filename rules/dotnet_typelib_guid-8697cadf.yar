rule Sightlines_dotnet_typelib_guid_8697cadf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-8697cadf"
        date = "2026-11-24"
        campaign = "dotnet_typelib_guid-8697cadf"
        family = ""
        hash = "0146037fdbbc10c032f9cacdcec08c2cfe7596848efe4393b7d854016a544499"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-8697cadf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xr:d:DAFkOmfVY_Y:9,j:48097866239,t:23052818tL<" ascii
        $s1 = "EData Source=TRONGMINH;Initial Catalog=qlcafe;Integrated Security=True" ascii
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "Data Source=TRONGMINH;Initial Catalog=master;Integrated Security=True" wide
        $s4 = "DELETE FROM TaiKhoan WHERE tendangnhap=N'{0}'" wide
        $s5 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "insert into hoadon values('{0}', NULL,'{1}', 0)" wide
        $s7 = "select * from taikhoan where tendangnhap=N'{0}' and matkhau='{1}'" wide
        $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s9 = "select id from hoadon where idBan='{0}' AND tinhtrang=0" wide
        $s10 = "xr:d:DAFkNjGXl8A:3,j:5624373844,t:23052814f-8" ascii
        $s11 = "insert into thongtinhoadon values(N'{0}',N'{1}',N'{2}')" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 5672960 and 12 of them
}
