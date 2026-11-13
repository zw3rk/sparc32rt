#!/usr/bin/env python3
"""Generate tests/guests/r13r16 and tests/guests/r14t2trap: end-to-end
regression guests for the Round 13-16 DBT remediation (S32-R14-1,
S32-R14-2, S32-R15-1, S32-R15-2).

SPARC V8 machine code is emitted directly (no cross toolchain needed);
every encoder is self-checked against reference words (ta 0x10, or,
subcc) before generation. The guest runs under --interp, --dbt, and
--difftest (see tests/check_r13_r16.sh); exit 0 means every check
passed, any other exit names the failing phase:

  10  ba with tn in delay slot lost the outer target (R14-2)
  11  rt_sigaction(102) setup failed (R14-2 harness)
  12  faulting delay reported the outer target as npc (R14-2)
  20  not-taken te 0x10 trapped (R14-1)
  21  taken te 0x10 fell through (R14-1)
  30  fstoi NaN result != 0x7FFFFFFF (R15-1)
  31  fstoi NaN FSR NVC missing (R15-1)
  32  fdtoi NaN result != 0x7FFFFFFF (R15-1)
  33  fdtoi NaN FSR NVC missing (R15-1)
  40  fadds two-QNaN payload wrong (R15-2)
  41  fadds two-QNaN raised flags (R15-2)
  42  faddd payload wrong (R15-2)
  43  faddd raised flags (R15-2)
  44  fadds SNaN result wrong (R15-2)
  45  fadds SNaN flags wrong (R15-2)
"""

import struct
import sys

G0, G1, O0, O1, O2, O3, O4, SP = 0, 1, 8, 9, 10, 11, 12, 14

words = []
labels = {}
fixups = []
absfixups = []


def emit(w):
    words.append(w & 0xFFFFFFFF)
    return len(words) - 1


def mark(name):
    assert name not in labels
    labels[name] = len(words) * 4


def B(op, rd, op3, rs1, second):
    assert 0 <= op < 4 and 0 <= rd < 32 and 0 <= op3 < 64
    assert 0 <= rs1 < 32
    return (op << 30) | (rd << 25) | (op3 << 19) | (rs1 << 14) | second


def f3(op, rd, op3, rs1, imm=None, rs2=None):
    if imm is not None:
        assert -(1 << 12) <= imm < (1 << 12)
        return B(op, rd, op3, rs1, (1 << 13) | (imm & 0x1FFF))
    return B(op, rd, op3, rs1, rs2 & 0x1F)


def orr(rd, rs1, imm=None, rs2=None):
    return f3(2, rd, 0x02, rs1, imm, rs2)


def add(rd, rs1, imm=None, rs2=None):
    return f3(2, rd, 0x00, rs1, imm, rs2)


def subcc(rd, rs1, imm=None, rs2=None):
    return f3(2, rd, 0x14, rs1, imm, rs2)


def ldw(rd, rs1, off):
    return f3(3, rd, 0x00, rs1, off)


def stw(rd, rs1, off):
    return f3(3, rd, 0x04, rs1, off)


def sethi(rd, imm22):
    assert 0 <= imm22 < (1 << 22)
    return (rd << 25) | (4 << 22) | imm22


def branch(cond, a, label):
    pos = emit(0)
    fixups.append((pos, cond, a, label))
    return pos


def trap(cond, rs1, num):
    return B(2, cond, 0x3A, rs1, (1 << 13) | (num & 0x7F))


def fpop(rd, rs1, opf, rs2):
    return B(2, rd, 0x34, rs1, ((opf & 0x1FF) << 5) | (rs2 & 0x1F))


def fmem(op3, rd, rs1, off):
    return f3(3, rd, op3, rs1, off)


NOP = sethi(0, 0)

# Encoder self-checks against known-good words.
assert trap(8, 0, 0x10) == 0x91D02010, hex(trap(8, 0, 0x10))
assert orr(1, 0, 1) == 0x82102001, hex(orr(1, 0, 1))
assert subcc(0, 0, 0) == 0x80A02000, hex(subcc(0, 0, 0))
assert trap(1, 0, 0x10) == 0x83D02010, hex(trap(1, 0, 0x10))
assert trap(0, 0, 0x00) == 0x81D02000, hex(trap(0, 0, 0x00))
assert sethi(1, 0) == 0x03000000

BASE = 0x10000
EH = 52
PH = 32


def mov_imm(rd, v):
    assert 0 <= v < (1 << 32)
    hi = (v >> 10) & 0x3FFFFF
    lo = v & 0x3FF
    emit(sethi(rd, hi))
    if lo:
        emit(orr(rd, rd, lo))


def fail(code):
    emit(orr(G1, G0, 1))
    emit(orr(O0, G0, code))
    emit(trap(8, 0, 0x10))
    emit(NOP)


def check_eq(reg, expect, code):
    """Branch to F<code> unless integer reg == expect (delay: nop).
    The expected value goes to O2 so a result already in O1 survives."""
    mov_imm(O2, expect)
    emit(subcc(G0, reg, rs2=O2))
    branch(9, 0, "F%d" % code)  # bne
    emit(NOP)


def mov_imm_label(rd, label, addend=0):
    """sethi/or pair patched to BASE+label+addend at link time."""
    p1 = emit(sethi(rd, 0))
    p2 = emit(orr(rd, rd, 0))
    absfixups.append((p1, p2, rd, label, addend))


def check_eq_label(reg, label, addend, code):
    """check_eq against a link-time address (expected value in O2)."""
    mov_imm_label(O2, label, addend)
    emit(subcc(G0, reg, rs2=O2))
    branch(9, 0, "F%d" % code)  # bne
    emit(NOP)


def exit_guest(code):
    emit(orr(G1, G0, 1))
    emit(orr(O0, G0, code))
    emit(trap(8, 0, 0x10))
    emit(NOP)


def fsr_zero():
    emit(stw(G0, SP, -8))
    emit(fmem(0x21, 0, SP, -8))  # ldfsr [%sp-8], %g0


def check_fsr(expect, code):
    emit(fmem(0x25, 0, SP, -8))  # stfsr [%sp-8]
    emit(ldw(O1, SP, -8))
    check_eq(O1, expect, code)


# -- Phase A (R14-2): ba with tn in delay must reach its target. --
emit(orr(O0, G0, 6))
branch(8, 0, "T1")
emit(trap(0, 0, 0x00))  # tn: delay, never traps
mark("T1")
emit(orr(O0, G0, 5))
emit(subcc(G0, O0, 5))
branch(9, 0, "F10")  # bne: target skipped means %o0 is still 6
emit(NOP)

# -- Phase A2 (R14-2): ba with a FAULTING delay must replay the pair
# atomically. The misaligned delay load raises SIGBUS; the handler
# records the entry npc (must be the delay address + 4, not the outer
# target) and resumes past the delay. Pre-fix code armed the jmpl
# record and exited SINGLE_STEP at npc, so the fault commit hijacked
# npc to the outer target (observed npc == T2 instead of TA+4). A fault
# (not a trap) is used so --difftest drives delivery on both copies and
# keeps comparing through the handler.
mov_imm_label(O1, "H")
emit(stw(O1, SP, -32))  # act.handler
emit(stw(G0, SP, -28))  # act.flags = 0
emit(stw(G0, SP, -24))  # act.restorer-in-struct = 0
emit(stw(G0, SP, -20))  # act.mask = 0
emit(stw(G0, SP, -16))
emit(orr(G1, G0, 102))  # rt_sigaction
emit(orr(O0, G0, 10))  # SIGBUS
emit(add(O1, SP, -32))  # act
emit(orr(O2, G0, 0))  # oact NULL
mov_imm_label(O3, "R")  # restorer
emit(orr(O4, G0, 8))  # sigsetsize
emit(trap(8, 0, 0x10))
emit(subcc(G0, O0, 0))
branch(9, 0, "F11")  # bne: sigaction must succeed
emit(NOP)
branch(8, 0, "T2")
mark("TA")
emit(ldw(O1, SP, 1))  # misaligned delay load: SIGBUS
mark("T2")
mov_imm_label(O1, "OBS")
emit(ldw(O1, O1, 0))
check_eq_label(O1, "TA", 4, 12)

# -- Phase B (R14-1): not-taken te 0x10 falls through (getpid stays 0). --
emit(orr(G1, G0, 20))  # getpid
emit(orr(O0, G0, 0))
emit(orr(O1, G0, 1))
emit(subcc(G0, O1, 0))  # Z=0
emit(trap(1, 0, 0x10))  # te: must NOT trap
emit(subcc(G0, O0, 0))
branch(9, 0, "F20")  # bne: trapped means %o0 is a pid
emit(NOP)

# -- Phase C (R14-1): taken te 0x10 performs getpid (%o0 becomes pid). --
emit(subcc(G0, G0, 0))  # Z=1
emit(trap(1, 0, 0x10))  # te: must trap into getpid
emit(subcc(G0, O0, 0))
branch(1, 0, "F21")  # be: fell through means %o0 is still 0
emit(NOP)

# -- Phase D (R15-1): fstoi on a quiet NaN. --
fsr_zero()
mov_imm(O1, 0x7FC00001)
emit(stw(O1, SP, -8))
emit(fmem(0x20, 0, SP, -8))  # ld [%sp-8], %f0
emit(fpop(1, 0, 0x0D1, 0))  # fstoi %f0, %f1
emit(fmem(0x24, 1, SP, -8))  # st %f1, [%sp-8]
emit(ldw(O1, SP, -8))
check_eq(O1, 0x7FFFFFFF, 30)
check_fsr(0x210, 31)

# -- Phase E (R15-1): fdtoi on a quiet double NaN. --
fsr_zero()
mov_imm(O1, 0x7FF80000)
emit(stw(O1, SP, -8))
mov_imm(O1, 0x5)
emit(stw(O1, SP, -4))
emit(fmem(0x23, 0, SP, -8))  # ldd [%sp-8], %f0
emit(fpop(1, 0, 0x0D2, 0))  # fdtoi %f0, %f1
emit(fmem(0x24, 1, SP, -8))  # st %f1, [%sp-8]
emit(ldw(O1, SP, -8))
check_eq(O1, 0x7FFFFFFF, 32)
check_fsr(0x210, 33)

# -- Phase F (R15-2): fadds on two quiet NaNs picks the larger frac. --
fsr_zero()
mov_imm(O1, 0x7FC00001)
emit(stw(O1, SP, -8))
emit(fmem(0x20, 0, SP, -8))  # %f0 = va
mov_imm(O1, 0x7FC00002)
emit(stw(O1, SP, -8))
emit(fmem(0x20, 1, SP, -8))  # %f1 = vb
emit(fpop(3, 0, 0x041, 1))  # fadds %f0, %f1, %f3
emit(fmem(0x24, 3, SP, -8))
emit(ldw(O1, SP, -8))
check_eq(O1, 0x7FC00002, 40)
check_fsr(0, 41)

# -- Phase G (R15-2): faddd reverse order picks va. --
fsr_zero()
mov_imm(O1, 0x7FF80000)
emit(stw(O1, SP, -8))
mov_imm(O1, 0x9)
emit(stw(O1, SP, -4))
emit(fmem(0x23, 0, SP, -8))  # %f0 = va (frac 9)
mov_imm(O1, 0x7FF80000)
emit(stw(O1, SP, -16))
mov_imm(O1, 0x3)
emit(stw(O1, SP, -12))
emit(fmem(0x23, 2, SP, -16))  # %f2 = vb (frac 3)
emit(fpop(4, 0, 0x042, 2))  # faddd %f0, %f2, %f4
emit(fmem(0x27, 4, SP, -8))  # std %f4, [%sp-8]
emit(ldw(O1, SP, -8))
check_eq(O1, 0x7FF80000, 42)
emit(ldw(O1, SP, -4))
check_eq(O1, 0x9, 42)
check_fsr(0, 43)

# -- Phase H (R15-2): SNaN + QNaN quiets the first input with NVC. --
fsr_zero()
mov_imm(O1, 0x7F800001)
emit(stw(O1, SP, -8))
emit(fmem(0x20, 0, SP, -8))  # %f0 = SNaN
mov_imm(O1, 0x7FC00002)
emit(stw(O1, SP, -8))
emit(fmem(0x20, 1, SP, -8))  # %f1 = QNaN
emit(fpop(3, 0, 0x041, 1))  # fadds %f0, %f1, %f3
emit(fmem(0x24, 3, SP, -8))
emit(ldw(O1, SP, -8))
check_eq(O1, 0x7FC00001, 44)
check_fsr(0x210, 45)

exit_guest(0)

# ================= guest 2: R14-2 trapping-delay npc =================
# A taken ba whose delay slot traps must report npc = branch target
# (interp_cti succ), not delay + 4. Pre-fix code exited SINGLE_STEP at
# npc, so the replay trapped with npc = TA + 4; the fix replays the
# whole pair, reporting npc = T2FAR. T2FAR is deliberately far from
# TA + 4 so the two outcomes differ. Guests 1 and 2 share the encoder
# helpers; emission state is reset here.
words1, labels1, fixups1, absfixups1 = words, labels, fixups, absfixups
words = []
labels = {}
fixups = []
absfixups = []

mov_imm_label(O1, "H2")
emit(stw(O1, SP, -32))  # act.handler
emit(stw(G0, SP, -28))
emit(stw(G0, SP, -24))
emit(stw(G0, SP, -20))
emit(stw(G0, SP, -16))
emit(orr(G1, G0, 102))  # rt_sigaction
emit(orr(O0, G0, 5))  # SIGTRAP
emit(add(O1, SP, -32))  # act
emit(orr(O2, G0, 0))  # oact NULL
mov_imm_label(O3, "R2")  # restorer
emit(orr(O4, G0, 8))  # sigsetsize
emit(trap(8, 0, 0x10))
emit(subcc(G0, O0, 0))
branch(9, 0, "F14")  # bne: sigaction must succeed
emit(NOP)
branch(8, 0, "T2FAR")
mark("TA2")
emit(trap(8, 0, 0x01))  # ta 1 delay: always traps (SIGTRAP)
exit_guest(98)  # unreachable: ba always taken, ta always traps
mark("T2FAR")
mov_imm_label(O1, "OBS2")
emit(ldw(O1, O1, 0))
check_eq_label(O1, "T2FAR", 0, 13)
exit_guest(0)

mark("H2")  # SIGTRAP handler: record entry npc, skip the delay.
emit(ldw(O1, SP, 0xE8))  # pt_regs.npc at entry
mov_imm_label(O2, "OBS2")
emit(stw(O1, O2, 0))
mov_imm_label(O1, "T2FAR")  # resume past the trapping delay
emit(stw(O1, SP, 0xE4))  # regs.pc = T2FAR
mov_imm_label(O1, "T2FAR", 4)
emit(stw(O1, SP, 0xE8))  # regs.npc = T2FAR+4
emit(orr(G1, G0, 101))  # rt_sigreturn
emit(trap(8, 0, 0x10))
emit(NOP)

mark("R2")  # restorer (unused: the handler sigreturns directly)
emit(orr(G1, G0, 101))
emit(trap(8, 0, 0x10))

mark("OBS2")
emit(0)

for code in (13, 14, 98):
    mark("F%d" % code)
    fail(code)

# Resolve branch fixups: disp22 = (target - pc) >> 2.
for pos, cond, a, label in fixups:
    pc = pos * 4
    disp = (labels[label] - pc) >> 2
    assert -(1 << 21) <= disp < (1 << 21), (label, disp)
    words[pos] = (a << 29) | (cond << 25) | (2 << 22) | (disp & 0x3FFFFF)

# Resolve absolute fixups: sethi/or pair for the link-time VA
# (code starts past the ELF header + program header: BASE + EH + PH).
for p1, p2, rd, label, addend in absfixups:
    va = BASE + EH + PH + labels[label] + addend
    hi = (va >> 10) & 0x3FFFFF
    lo = va & 0x3FF
    words[p1] |= hi
    words[p2] |= lo
    assert (words[p1] >> 25) & 0x1F == rd
    assert (words[p2] >> 25) & 0x1F == rd

code2 = b"".join(struct.pack(">I", w) for w in words)

entry_off = EH + PH
e_entry = BASE + entry_off
ehdr = struct.pack(">16sHHIIIIIHHHHHH",
    b"\x7fELF\x01\x02\x01\x00" + b"\x00" * 8,
    2, 2, 1, e_entry, EH, 0, 0, EH, PH, 1, 0, 0, 0)
filesz = entry_off + len(code2)
phdr = struct.pack(">IIIIIIII", 1, 0, BASE, BASE, filesz, filesz, 7, 0x1000)
with open("tests/guests/r14t2trap", "wb") as f:
    f.write(ehdr)
    f.write(phdr)
    f.write(code2)
print("wrote tests/guests/r14t2trap (%d bytes, entry 0x%x)" % (filesz,
    e_entry))

words, labels, fixups, absfixups = words1, labels1, fixups1, absfixups1

# ================= guest 1 tail (defined above) =================

mark("H")  # SIGBUS handler: record entry npc, skip the delay.
emit(ldw(O1, SP, 0xE8))  # pt_regs.npc at entry
mov_imm_label(O2, "OBS")
emit(stw(O1, O2, 0))
mov_imm_label(O1, "T2")  # resume past the trapping delay
emit(stw(O1, SP, 0xE4))  # regs.pc = T2
mov_imm_label(O1, "T2", 4)
emit(stw(O1, SP, 0xE8))  # regs.npc = T2+4
emit(orr(G1, G0, 101))  # rt_sigreturn
emit(trap(8, 0, 0x10))
emit(NOP)

mark("R")  # restorer (unused: the handler sigreturns directly)
emit(orr(G1, G0, 101))
emit(trap(8, 0, 0x10))

mark("OBS")
emit(0)

for code in (10, 11, 12, 20, 21, 30, 31, 32, 33, 40, 41, 42, 43, 44, 45):
    mark("F%d" % code)
    fail(code)

# Resolve branch fixups: disp22 = (target - pc) >> 2.
for pos, cond, a, label in fixups:
    pc = pos * 4
    disp = (labels[label] - pc) >> 2
    assert -(1 << 21) <= disp < (1 << 21), (label, disp)
    words[pos] = (a << 29) | (cond << 25) | (2 << 22) | (disp & 0x3FFFFF)

# Resolve absolute fixups: sethi/or pair for the link-time VA
# (code starts past the ELF header + program header: BASE + EH + PH).
for p1, p2, rd, label, addend in absfixups:
    va = BASE + EH + PH + labels[label] + addend
    hi = (va >> 10) & 0x3FFFFF
    lo = va & 0x3FF
    words[p1] |= hi
    words[p2] |= lo
    assert (words[p1] >> 25) & 0x1F == rd
    assert (words[p2] >> 25) & 0x1F == rd

entry_off = EH + PH
code = b"".join(struct.pack(">I", w) for w in words)
phdr_off = EH
e_entry = BASE + entry_off
ehdr = struct.pack(">16sHHIIIIIHHHHHH",
    b"\x7fELF\x01\x02\x01\x00" + b"\x00" * 8,
    2, 2, 1, e_entry, phdr_off, 0, 0, EH, PH, 1, 0, 0, 0)
filesz = entry_off + len(code)
phdr = struct.pack(">IIIIIIII", 1, 0, BASE, BASE, filesz, filesz, 7, 0x1000)
out = sys.argv[1] if len(sys.argv) > 1 else "tests/guests/r13r16"
with open(out, "wb") as f:
    f.write(ehdr)
    f.write(phdr)
    f.write(code)
print("wrote %s (%d bytes, entry 0x%x)" % (out, filesz, e_entry))
