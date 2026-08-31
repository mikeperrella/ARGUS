rule AgentTesla_PrivacyShield_DotNet_Crypter
{
    meta:
        description = "Detects .NET crypter/loader stub using custom 'PrivacyShield' crypto module (ribbon/slab XOR-permutation cipher, HMAC-SHA256, Rfc2898DeriveBytes) commonly used to protect AgentTesla and similar payloads"
        author = "argus-detection-eng"
        family = "AgentTesla-loader"
        reference = "0d736040f6fcab61ef390639d0f9deb1270c8b3492dd7abd9cdc8ec43a100364"

    strings:
        // PE/.NET structural markers
        $mz = "MZ"
        $net_sig = "BSJB"

        // Custom crypto module identifiers (unusual, family-specific naming)
        $mod1 = "PrivacyShield" ascii
        $mod2 = "PrivacyShield.dll" ascii
        $mod3 = "MarbleOracle" ascii
        $mod4 = "FrostStream" ascii

        // custom cipher primitive names
        $c1 = "ribbonA" ascii
        $c2 = "ribbonB" ascii
        $c3 = "ribbonC" ascii
        $c4 = "ribbonD" ascii
        $c5 = "GatherSlabs" ascii
        $c6 = "ExpandRibbons" ascii
        $c7 = "BuildAlpha" ascii
        $c8 = "Unweave" ascii
        $c9 = "Permute" ascii
        $c10 = "Unseal" ascii

        // size/config constants used by the cipher
        $s1 = "SLAB_SIZE" ascii
        $s2 = "NONCE_SIZE" ascii
        $s3 = "TAG_SIZE" ascii
        $s4 = "GRAIN_SIZE" ascii
        $s5 = "RIBBON_SIZE" ascii
        $s6 = "STRETCH_ROUNDS" ascii

        // supporting crypto API usage typical for the key-derivation/HMAC scheme
        $api1 = "Rfc2898DeriveBytes" ascii
        $api2 = "HMACSHA256" ascii
        $api3 = "CreateDecryptor" ascii
        $api4 = "TransformFinalBlock" ascii

    condition:
        $mz at 0
        and $net_sig
        and (
            1 of ($mod1, $mod2, $mod3, $mod4)
            and 4 of ($c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9, $c10)
            and 3 of ($s1, $s2, $s3, $s4, $s5, $s6)
            and 2 of ($api1, $api2, $api3, $api4)
        )
}