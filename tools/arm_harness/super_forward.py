"""objc_msgSendSuper2 spill-forwarder differential (shared harness module).

Generic capability added for the LEVEL-B executed differentials of the
`initWithWorld:dynamicWorld:saveDict:cache:…` forwarding convention: the
ORIGINAL ARM body spills its incoming arguments into an outgoing call frame and
re-dispatches them through `objc_msgSendSuper2` with its own-class superref.
This module owns the Unicorn glue for that shape:

  * patch the `objc_msgSendSuper2` GOT slot to a stub page (and optionally any
    extra GOT slot, e.g. `objc_msgSend`, to prove the body sends nothing else);
  * run the original body from its IMP with a caller-supplied incoming layout
    (r0..r3 + N stacked words);
  * at the stub, decode and record the observable ABI surface:
      - the `objc_super` struct word pair {receiver, class},
      - the selector string,
      - the register arguments (r2, r3) and the stacked arguments,
      - the return value the body produced (r0 at the stop address),
      - the ordered list of stub hits.
  * return that record so a thin per-batch shell can assert the ABI placement
    (independent of any recovered contract) and compare the forwarded tuple and
    call order against the recovered C++.

Boundary: this is a synthetic ObjC message graph, not Foundation and not the
original-app runtime; the superclass initialiser is a stub. A shell using this
module must state that boundary in its own report.
"""
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_PC,
                               UC_ARM_REG_LR)

DEFAULT_STUB = 0x72000000


class SuperForwardDifferential:
    """Runs spill-forwarder bodies and records what they forward to super."""

    def __init__(self, session, super2_got, n_stack=4, stub=DEFAULT_STUB,
                 extra_stubs=None):
        """session    — arm_harness.loader.ARMSession (ELF mapped, VFP enabled).
        super2_got — the objc_msgSendSuper2 GOT/JUMP_SLOT address in the ELF.
        n_stack    — how many stacked argument words the selector carries.
        extra_stubs— {got_slot: tag}: additional GOT slots patched to extra stub
                     pages; a hit is recorded as that tag (used to prove a body
                     sends nothing but the one super message)."""
        self.session = session
        self.uc = session.uc
        self.n_stack = n_stack
        self.super2_got = super2_got
        self.stub = stub
        self.calls = []
        self.super_result = 0
        self.selector_limit = 160

        session.patch_got(super2_got, stub)
        self.uc.mem_map(stub, 0x1000)
        self._tags = {stub: 'super2'}
        base = stub + 0x1000
        for slot, tag in (extra_stubs or {}).items():
            self.uc.mem_map(base, 0x1000)
            session.patch_got(slot, base)
            self._tags[base] = tag
            base += 0x1000
        for addr in self._tags:
            self.uc.hook_add(UC_HOOK_CODE, self._on_stub, begin=addr,
                             end=addr + 4)

    # -- stub ---------------------------------------------------------------
    def _word(self, at):
        return self.session.read_word(at)

    def _cstring(self, at):
        return bytes(self.uc.mem_read(at, self.selector_limit)) \
            .split(b'\0')[0].decode('ascii', 'replace')

    def _on_stub(self, uc, address, size, data):
        tag = self._tags[address]
        entry: dict = {'stub': tag}
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if tag == 'super2':
            # r0 = &struct objc_super {receiver, class}; r1 = selector.
            entry['super_receiver'] = self._word(r0)
            entry['super_class'] = self._word(r0 + 4)
            sel_ptr = uc.reg_read(UC_ARM_REG_R1)
            entry['selector'] = self._cstring(sel_ptr)
            r2 = uc.reg_read(UC_ARM_REG_R2)
            r3 = uc.reg_read(UC_ARM_REG_R3)
            sp = uc.reg_read(UC_ARM_REG_SP)
            stack = tuple(self._word(sp + 4 * i) for i in range(self.n_stack))
            entry['forward'] = (r2, r3) + stack
            uc.reg_write(UC_ARM_REG_R0, self.super_result)
        else:
            entry['receiver'] = r0
            entry['selector'] = self._cstring(uc.reg_read(UC_ARM_REG_R1))
            uc.reg_write(UC_ARM_REG_R0, 0)
        self.calls.append(entry)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    # -- run ----------------------------------------------------------------
    def run(self, imp, receiver, cmd, r2, r3, stack_args, super_result,
            count=20000):
        """Run one case. Returns a record dict.

        receiver  — the object in r0 (also what [super …] must receive).
        cmd       — r1 (the body does not read _cmd; pass a token).
        r2, r3    — first two register arguments forwarded to super.
        stack_args— list of n_stack stacked argument words.
        super_result — the value the stubbed super returns (0 == nil).
        """
        assert len(stack_args) == self.n_stack, 'stack argument count'
        self.calls = []
        self.super_result = super_result
        sp = self.session.stack + 0x8000
        for off, value in enumerate(stack_args):
            self.session.word(sp + 4 * off, value)
        for reg, value in ((UC_ARM_REG_R0, receiver), (UC_ARM_REG_R1, cmd),
                           (UC_ARM_REG_R2, r2), (UC_ARM_REG_R3, r3)):
            self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM_REG_SP, sp)
        self.uc.reg_write(UC_ARM_REG_LR, self.session.stop)
        self.uc.emu_start(imp, self.session.stop, count=count)
        assert self.uc.reg_read(UC_ARM_REG_PC) == self.session.stop, \
            'method did not return'
        return {'call_return': self.uc.reg_read(UC_ARM_REG_R0),
                'calls': list(self.calls)}
