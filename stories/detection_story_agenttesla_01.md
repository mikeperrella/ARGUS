# Detection Story: AgentTesla — 0d736040f6fcab61ef390639d0f9deb1270c8b3492dd7abd9cdc8ec43a100364

## TTP Investigated

**T1620 – Reflective Code Loading**: This is the primary TTP directly confirmed through my own pipeline. CAPA matched `GetManifestResourceStream`, `Assembly::Load`, `GetMethod`, and `MethodBase::Invoke` in the sample, together showing a loader that pulls an embedded resource, loads it as an assembly in memory, locates a method via reflection, and executes it without a normal disk-based execution path.

**T1055.012 – Process Injection**:

Originally, I described T1055.012 as an externally reported behavior because the only direct reporting I had at the time came from Joe Sandbox, Hatching Triage, and Dr.Web vxCube. After going back through the static analysis more closely, I found additional evidence that makes this more than just a behavior reported by outside sandbox tools. I would characterize T1055.012 as static evidence consistent with a likely process injection/execution mechanism, but not fully confirmed. The static analysis shows three separate methods across two different classes, `GenMath` and `Utils`, that are independently gated and eventually chain together to call `AC1_1.OrderWorkflow.ProcessFulfillment`. That call passes a literal path to `MSBuild.exe` along with a decrypted byte blob. The call is also routed through `EarleyParser.InvokeViaILVoid`, which dynamically builds the `Assembly.Load` → `GetType` → `GetMethod` → `Invoke` sequence using `DynamicMethod` and `ILGenerator::Emit` instead of directly calling those APIs. This makes the reflection chain harder to identify through normal static analysis. The important limitation is that `OrderWorkflow` and `ProcessFulfillment` are part of an assembly that is decrypted and loaded entirely in memory at runtime, so the actual behavior of that method is not present in the static sample. Because the sample was never executed as part of this project, I cannot confirm exactly what happens after that point. MSBuild is a well-known living-off-the-land binary that is commonly abused for in-memory execution and injection, so its presence here is significant, but that connection is my own analysis and inference rather than something explicitly stated by CAPA or the sandbox reports.

## Raw Findings

**Reflective loading chain**: This loader pulls an embedded resource via `GetManifestResourceStream`, then loads it into memory with `Assembly.Load`. The surrounding SHA256 hashing and PRNG calls suggest the payload is decrypted or decoded first. Once loaded, it locates the target method with `GetMethod` and executes it via `MethodBase.Invoke`, running the payload entirely in memory without writing it to disk. Separately, CAPA flagged `Reflection.Emit` usage (`DynamicMethod`, `ILGenerator::Emit`), meaning the loader can also generate method bodies dynamically at runtime rather than only invoking pre-existing ones.

The reflective loading behavior is more complex than I originally described. I initially focused on CAPA's token 100663366/100663584 matches as if the behavior was concentrated in a single loader chain, but further manual analysis showed that there are at least three separate methods involved. `GenMath.WeightedMedian` (RID 70) and `Utils.Perpendicular` (RID 288) each contain their own version of the behavior, while `EarleyParser.InvokeViaILVoid` (RID 169) provides the runtime reflection mechanism that ultimately performs the dynamic invocation. `BaseGrammar.EstimateProbabilities` (RID 211) also acts as part of the chain because it resolves the type name `AC1_1.OrderWorkflow`, even though it does not directly call a reflection API itself.

I also corrected an earlier assumption about the decryption step. I previously stated that CAPA did not identify a direct decryption API and that the decryption was therefore inferred. That is no longer accurate. The decryption is confirmed because the actual `_Decrypt` calls were identified directly in the source, once in RID 70 and again in RID 288. CAPA does not flag this as a standard decryption API because `_Decrypt` is a custom method inside `PrivacyShield.dll` rather than a recognized cryptographic API. That is important because it shows how relying only on automated tool output could miss part of the behavior.

Another finding is that the disguise pattern appears to be systematic rather than limited to one hidden function. I confirmed two separate decoy methods so far: `GenMath.WeightedMedian` and `Utils.Perpendicular`. Both have normal-looking mathematical utility names and signatures, but both contain hidden behavior and their own separate `_Decrypt` calls. The four methods—`ToArrayString`, `Repeat`, `Sign`, and `Perpendicular(Vector2)`—are the only places in the entire assembly that contribute to `_resolvedLayerMask`, and together they can add up to no more than 30, while the gate requires exactly 31. Because of that, the branch cannot actually be triggered as written, which makes me believe this is either dead/decoy code or a bug in the sample, although I would leave the exact reason as an open question rather than state it as certain. Taken together, this looks more like multiple disguised trigger points spread across the codebase than a single isolated malicious function.

The naming disguise also extends to fields and type references. `GenMath.LightProbeAtlas` appears to be related to graphics or lighting data but actually holds the in-memory second-stage assembly. `Mathf.ShadowMapSlice` sounds like rendering data but actually contains the decrypted payload bytes. `BaseGrammar._gpuKernel` looks like a GPU-related field but actually stores a System.Type reference, and `Utils._resolvedLayerMask` appears to be a rendering or physics layer mask but is actually used as a gate counter. This indicates that the naming obfuscation was applied not only to methods, but also to the variables and fields used to move data through the different stages of the chain.

**PDB / crypter fingerprint**: CAPA matched a PDB path containing both `LX_CRYPTER` and the build identifier `LX_AYkvMzqX_0W`. FLOSS independently found `LX_AYkvMzqX_0W` again, in the PE version-info strings (`InternalName`, `OriginalFilename`). The build identifier is corroborated by two independent tools; `LX_CRYPTER` itself appears only once, in that single PDB path, so it's a possible indicator of the build tool or environment rather than a confirmed crypter name.

**File-system discovery calls**: CAPA matched four related capabilities: checking whether a file exists (`File::Exists`), resolving common system paths (`Environment::GetFolderPath`), creating a directory (`Directory::CreateDirectory`), and writing text to disk (`File::WriteAllText`). Only the first two carry an explicit ATT&CK T1083 (File and Directory Discovery) tag in this ruleset; directory creation and file writing are observed filesystem-modification capabilities, not tagged discovery behavior, and shouldn't be lumped in as if they were.

**DIE entropy**: Overall file entropy is 6.61, under the spec's 7.0 packing-gate threshold. But the `.text` section alone measures 6.63, and DIE's internal per-section heuristic independently flags it as "packed." That's a real, elevated signal worth noting, but it's a heuristic judgment on one section, not proof the sample as a whole is packed.

## Candidate Rule v1

```yara
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
```

## Validation Failure / Noise

The first validation pass succeeded on both tests. The YARA rule correctly matched `AgentTesla_PrivacyShield_DotNet_Crypter` on the known sample, while producing 0 hits across 300 `.exe`/`.dll` files from `C:\Windows\System32`. No rule-tightening iteration was needed, although the clean corpus was limited to native Windows system binaries, so this result does not establish the false-positive rate against other .NET software.

## The Tuned Rule

Identical to Candidate Rule v1 above. No edits were made before acceptance; the rule was accepted as-is after passing validation on the first attempt.

## Residual Blind Spots

This rule's biggest weakness is that it depends entirely on literal strings being present in the file. YARA only matches exact byte sequences, it has no understanding of behavior, so if the crypter author renames `PrivacyShield`, the module/class names, or the API-related strings in a future build, this rule would very likely miss it even though the underlying behavior, reflective loading, decryption, the same injection chain, stays identical. This risk isn't hypothetical here: the `.text` section already showed elevated entropy (6.63, flagged "packed" by DIE), suggesting this crypter's toolkit already leans toward obfuscation, and further string-level hiding would be a natural next step for its author.

Separately, the rule's metadata labels it `family = "AgentTesla-loader"`, but every condition it actually checks is specific to this one crypter's internal naming, not to AgentTesla itself. Nothing in the rule references anything AgentTesla-specific. That means it would almost certainly miss an AgentTesla sample wrapped in a different crypter, and by the same logic, it could just as easily fire on some other malware family entirely, if that family happened to reuse this same crypter service. The rule is really a fingerprint of this specific crypter/build, not a detection of AgentTesla as a family, and the metadata label overstates what the condition logic actually targets.

Given both of these, I'd treat this rule as a narrow, build-specific fingerprint rather than a durable behavioral detection, useful for catching this exact sample or near-identical rebuilds from the same crypter, but not something to rely on for the malware family more broadly.

One additional blind spot is that the complete chain was only identified through manual source analysis across multiple methods and classes. CAPA's default ruleset identified individual behaviors independently, but it did not connect the separate matches into one larger chain such as `LightProbeAtlas` → `_gpuKernel` → `ShadowMapSlice` → `OrderWorkflow`. This means that a detection approach based only on individual CAPA matches, or a YARA rule built around those isolated function-level indicators, could potentially detect pieces of the behavior without recognizing how those pieces work together as a multi-stage execution chain. This is an important limitation because the malicious behavior is not necessarily obvious from any one function by itself; the relationship between the methods, fields, trigger conditions, decryption steps, and runtime reflection is what makes the overall mechanism apparent.
