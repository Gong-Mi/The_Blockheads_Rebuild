"""Shared Unicorn ARM harness library for the B-line executed differentials.

Consolidates the fixture patterns proven in batches b4a..b4g so each new
LEVEL-B slice builds its world on top of this instead of re-deriving the
scaffolding from the skill notes:

* loader.ARMSession  — SHA-gated ELF load, PT_LOAD page mapping, VFP enable,
                       run-to-stop helper.
* graph.FixtureGraph — synthetic instance/save-dict memory: CFString objects
                       (resolved through the +8 data pointer), per-key boxed
                       values, token objects.
* dispatch.MsgDispatcher — selector-string msgSend stub with a handler table
                       (the body loads selectors from its own selref cells, so
                       the stub dispatches on the real ELF strings).
* world.WorldAnswers — the 0xa12f24 world-accessor answer set
                       (worldWidthMacro / macroTiles, per batch b4e) with a
                       per-call argument recorder.

Boundary: synthetic graph only — not Foundation, not the original-app
runtime. Every harness must still state its own stub limits in the report.
"""
from .loader import ARMSession
from .graph import FixtureGraph
from .dispatch import MsgDispatcher
from .world import WorldAnswers

__all__ = ['ARMSession', 'FixtureGraph', 'MsgDispatcher', 'WorldAnswers']
