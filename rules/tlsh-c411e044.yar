rule Sightlines_tlsh_c411e044_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c411e044"
        date = "2026-11-10"
        campaign = "tlsh-c411e044"
        family = ""
        hash = "50a3617137f6266d4d450230a6754ca3aa43ddb183159cd47041e83d54b629ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c411e044.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s2 = "SELECT MaVaiTro FROM NguoiDung WHERE TenDangNhap = @username AND MatKhau = @password" wide
        $s3 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
        $s4 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s5 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" ascii
        $s6 = "DOANHEQTCSDL.BitmapChannelStreaming.resources" ascii
        $s7 = "UPDATE ChiTietPhieuNhap SET SoLuong = {4}, GiaNhap = {5} WHERE MaPhieuNhap = {0} AND MaSanPham = {1}" wide
        $s8 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" ascii
        $s9 = "Data Source=NTDyy;Initial Catalog=QuanLyShopQuanAo_HeQTCSDL;Integrated Security=True" wide
        $s10 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s11 = "INSERT INTO ChiTietPhieuNhap (MaPhieuNhap, MaSanPham, MaMauSac, MaKichThuoc, SoLuong, GiaNhap) VALUE" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1983488 and 12 of them
}
