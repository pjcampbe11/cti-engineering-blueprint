import "hash"

rule HYP_2026_001_hashset
{
    meta:
        hypothesis = "HYP-2026-001"
        description = "Known sample hashes from CTI pipeline - retro sweep only"
    condition:
        hash.sha256(0, filesize) == "8a83d94d44b74afe4f81305048bf6e5b3f5f5ba22a2947652fdcf5b83290fc8c"
        or hash.sha256(0, filesize) == "aa2f4fa70b74a4b8851e3247959596141665da2a6bb16b4d52db4fc81653a707"
}
