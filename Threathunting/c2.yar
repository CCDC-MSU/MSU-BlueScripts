rule IMIX
{
    meta:
        description = "Detects files at least 500KB containing IMIX_ string"
        author = "Claude"
        date = "2025-11-26"
    
    strings:
        $imix = "IMIX_" ascii wide
    
    condition:
        filesize >= 500000 and $imix
}

