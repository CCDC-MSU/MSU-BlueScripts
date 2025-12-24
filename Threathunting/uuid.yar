rule UUID
{
    meta:
        description = "Detects files containing only a UUID"
        reference = "UUID v4 has version=4 and variant bits 10xx"
        
    strings:
        // Fast literal anchor - UUID v4 always has "-4" at position 14-16
        $anchor = "-4" ascii
        
        // Full UUID v4 pattern with dashes
        $uuid_v4 = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}/ ascii
        
    condition:
        filesize == 36 and 
        $anchor and
        $uuid_v4 at 0
}
