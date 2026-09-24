"""The 0xa12f24 world-accessor answer set (batch b4e lesson).

The world accessor dispatches through the 0x1c281c veneer slot and asks the
world only the questions configured here — "answer only the queries
actually observed". Stage the answers in a small table and hook the
accessor at its first instruction.
"""
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, \
    UC_ARM_REG_PC, UC_ARM_REG_LR

ACCESSOR_IMP = 0x00A12F24


class WorldAnswers:
    def __init__(self, uc, accessor_imp=ACCESSOR_IMP):
        self.uc = uc
        self.accessor_imp = accessor_imp
        self.answers = {}
        self.calls = []
        # Optional per-call assertion invoked INSIDE the hook (call-time
        # memory state) — the b4g port lesson: asserting after the run
        # compares against mutated state when a stub scripts changes.
        self.on_call = None

    def set(self, selector, value):
        self.answers[selector] = value

    def install(self):
        uc = self.uc

        def hook(uc_, address, size, data):
            x = uc_.reg_read(UC_ARM_REG_R0)
            y = uc_.reg_read(UC_ARM_REG_R1)
            if self.on_call is not None:
                self.on_call(x, y)
            self.calls.append((x, y))
            uc_.reg_write(UC_ARM_REG_R0, 0)  # stage-1 fixture: nil tile
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

        uc.hook_add(UC_HOOK_CODE, hook, begin=self.accessor_imp,
                    end=self.accessor_imp + 4)
