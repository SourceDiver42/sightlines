rule Sightlines_dotnet_typelib_guid_f6fda1a6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f6fda1a6"
        date = "2026-11-10"
        campaign = "dotnet_typelib_guid-f6fda1a6"
        family = ""
        hash = "299cf4eb921023775ed82cdd58aaf3f25b93cde115bfe08db81b5caf920ec864"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f6fda1a6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SELECT * FROM DBO.FindInfoProduct(@product_name, @size, @color, @branch_id)" wide
        $s1 = "SELECT * FROM DBO.FindColorBySize(@size, @product_name)" wide
        $s2 = "SELECT * FROM DBO.FindProductNameByID(@product_id)" wide
        $s3 = "SELECT * FROM DBO.FindProductByName(@product_name)" wide
        $s4 = "SELECT * FROM DBO.FindColorByName(@product_name)" wide
        $s5 = "SELECT * FROM DBO.FindSizeByName(@product_name)" wide
        $s6 = "SELECT * FROM DBO.FindCustomerByName(@full_name)" wide
        $s7 = "SELECT * FROM DBO.FindMonthSummaryByID(@employee_id)" wide
        $s8 = "SELECT * FROM DBO.FindSizeByColor(@color, @product_name)" wide
        $s9 = "SELECT * FROM DBO.FindProductNameByName(@product_name)" wide
        $s10 = "SELECT * FROM DBO.FindProductTypeByName(@product_type_name)" wide
        $s11 = "SELECT * FROM DBO.FindCustomerByID(@customer_type_id)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 7970816 and 12 of them
}
