rule Sightlines_tlsh_7729d32a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7729d32a"
        date = "2026-11-26"
        campaign = "tlsh-7729d32a"
        family = ""
        hash = "2bd89f6900f2a7ee38d47c73166a3ea7c04f93852ba689739aefe0100a6cb727"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7729d32a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "net/runelite/api/events/VolumeChanged$Type.classPK" ascii
        $s1 = "net/runelite/api/geometry/RectangleUnion$Chunk.classPK" ascii
        $s2 = "net/runelite/api/geometry/SimplePolygon$TransformIterator.classPK" ascii
        $s3 = "net/runelite/api/geometry/RectangleUnion$ChangingState.classPK" ascii
        $s4 = "net/runelite/api/geometry/SimplePolygon$SimpleIterator.classPK" ascii
        $s5 = "net/runelite/api/geometry/Shapes$ShapeIterator.classPK" ascii
        $s6 = "net/runelite/api/geometry/RectangleUnion$Segments.classPK" ascii
        $s7 = "net/runelite/api/geometry/RectangleUnion$Segment.classPK" ascii
        $s8 = "net/runelite/api/geometry/RectangleUnion$Rectangle.classPK" ascii
        $s9 = "net/runelite/api/annotations/PK" ascii
        $s10 = "net/runelite/api/worldmap/PK" ascii
        $s11 = "net/runelite/api/geometry/PK" ascii
    condition:
        filesize < 1048576 and 12 of them
}
