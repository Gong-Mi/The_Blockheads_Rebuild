#!/usr/bin/env python3
"""Dual-mode guard for the b5b plant_full batch and the record-key dispatch.

Local (with the pinned ELF): verifies the evidence files the batch claims.
CI (no ELF): locks the contract surfaces that must not drift silently:
  - the dw record-key type evidence document exists with its key claims;
  - plant_full.h/cpp compile-shaped invariants: the factory exists, the
    recovered Plant chain is referenced, TulipPlant's own keys are listed,
    the factory EXECUTES the chain (plant_full_load) and hands the state out
    (out_state), and the impossible empty extract stub stays removed;
  - original_client_app.cpp routes by the record key FIRST (primary), keeps
    objectType/dynamicObjectType only as fallback, and counts disagreement;
  - the CMake test target is registered so the contract actually executes.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(path: Path, needles) -> None:
    text = path.read_text(encoding="utf-8")
    missing = [n for n in needles if n not in text]
    if missing:
        raise SystemExit(f"{path.name} missing: {missing}")


def main() -> None:
    native = ROOT / "reconstruction/reverse-v3/native"
    require(native / "DW_RECORD_KEY_TYPE_EVIDENCE.md",
            ["%d_%d/%d", "%@_%d_%d/%d", "record_key",
             "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"])
    require(ROOT / "reconstruction/recovered/plant_full.h",
            ["plant_full_load", "plant_full_factory", "TulipPlantFields",
             "season_gate", "loadSaveDictValues", "PlantFullState* out_state"])
    require(ROOT / "reconstruction/recovered/plant_full.cpp",
            ["hasFloweredThisSeason", "growthRateGene", "maxAgeGene",
             "mateColorGenes", "mixGenes", "availableFood", "1800.0"])
    # The factory must EXECUTE the recovered chain, not merely relabel a stub,
    # and the empty extract stub (which could not return the state) must not
    # come back: the state flows through the out_state parameter instead.
    cpp = (ROOT / "reconstruction/recovered/plant_full.cpp").read_text()
    factory_at = cpp.index("ClientDynamicObject plant_full_factory")
    assert "plant_full_load({" in cpp[factory_at:], \
        "the factory must run the recovered chain"
    assert "out_state" in cpp[factory_at:], "the factory must hand the state out"
    assert "plant_full_extract" not in cpp, "the empty extract stub must not come back"
    header = (ROOT / "reconstruction/recovered/plant_full.h").read_text()
    assert "plant_full_extract" not in header, \
        "the empty extract stub must not come back; use the out_state parameter"
    app = ROOT / "app/src/main/cpp/original_client_app.cpp"
    require(app,
            ['record_key', '"objectType"', '"dynamicObjectType"',
             '"type_disagreement"', "key_type_id"])
    # primary order: the record-key branch must precede the fallback branch;
    # anchor on the typed block itself (a bare "} else {" appears earlier in
    # open(), so the fallback anchor must be searched AFTER the key branch)
    text = app.read_text(encoding="utf-8")
    key_branch = text.index("if (key_type_id >= 0) {")
    fallback_branch = text.index("} else {", key_branch)
    assert key_branch < fallback_branch, "record key must be the primary source"
    # the fallback branch must read the dictionary itself (suffix-less keys
    # only) and route to unidentified when no type key exists
    fallback = text[fallback_branch:]
    assert 'objectForKey("objectType")' in fallback, \
        "the fallback branch must read objectType itself"
    assert "unidentified_objects" in fallback, \
        "a suffix-less entry without a type key must count unidentified"
    # disagreement is counted only inside the record-key branch (typed
    # routing), never in the fallback branch
    key_block = text[key_branch:fallback_branch]
    assert '"type_disagreement"' in key_block, \
        "type_disagreement must be counted in the record-key branch"
    cmake = ROOT / "reconstruction/recovered/CMakeLists.txt"
    require(cmake, ["plant_full.cpp", "test_plant_full", "add_test(NAME plant_full"])
    print("plant-full-b5b-evidence: PASS")


if __name__ == "__main__":
    main()
