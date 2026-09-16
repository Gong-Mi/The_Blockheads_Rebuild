#!/usr/bin/env python3
"""Hash-pinned, complete word/constant extraction for projection callback/helper."""
import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly
from recover_gameview_update_boundary import expand_vfp_immediate

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
START, END = 0x92ef38, 0x92f298

def recover(path):
    memory = ELFMemory(path)  # SHA256/ABI gate before fixed-address reads.
    command = ['r2', '-q', '-e', 'scr.color=false', '-e', 'bin.relocs.apply=true',
               '-e', 'asm.arch=arm', '-e', 'asm.bits=32', '-c',
               f'pdj {(END-START)//4} @ {START};q', str(path)]
    rows = json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)
    text = '# Full ARM words, including literal pools (pool mnemonics are not code).\n'
    text += '# callback code [0x92ef38,0x92f150); pool [0x92f150,0x92f170)\n'
    text += '# helper code [0x92f170,0x92f294); zero literal [0x92f294,0x92f298)\n'
    for row in rows:
        text += f"0x{row.get('addr', row.get('offset')):08x}  {row['bytes']}  {row.get('opcode', 'invalid')}\n"
    count = verify_disassembly(memory, text, START, END)
    with path.open('rb') as stream:
        symbols = {s['st_value']: s.name for s in ELFFile(stream).get_section_by_name('.dynsym').iter_symbols()}
    base = (0x92ef4c + 8 + memory.word(0x92f16c)) & 0xffffffff
    fields = []
    for literal, suffix, offset in [(0x92f158,'pinchScale',152), (0x92f15c,'windowInfo',208),
                                    (0x92f168,'projectionMatrix',48), (0x92f160,'cameraZ',112)]:
        slot = (base + memory.word(literal)) & 0xffffffff
        pointer = memory.word(slot)
        name = symbols.get(pointer)
        assert name == 'OBJC_IVAR_$_GameView.' + suffix, (hex(literal), name)
        assert memory.word(pointer) == offset
        fields.append(dict(literal=hex(literal), slot=hex(slot), symbol=name, offset=offset))
    constants = []
    for address, width, expected in [(0x92ef54,64,1), (0x92f094,32,0.5), (0x92f124,32,2),
                                     (0x92f190,32,2), (0x92f1d0,32,2), (0x92f1d8,32,-1), (0x92f1e0,32,1)]:
        word = memory.word(address)
        imm8 = ((word >> 16) & 15) << 4 | (word & 15)
        value = expand_vfp_immediate(imm8, width)
        assert value == expected
        constants.append(dict(address=hex(address), instruction_word=hex(word), width=width, imm8=imm8, value=value))
    literals = []
    for address, width in [(0x92f150,64), (0x92f164,32), (0x92f294,32)]:
        raw = b''.join(memory.word(a).to_bytes(4,'little') for a in range(address,address+width//8,4))
        value = struct.unpack('<d' if width==64 else '<f',raw)[0]
        literals.append(dict(address=hex(address), raw_le=raw.hex(), value=value, hex_float=value.hex()))
    assert literals[0]['value'] == float.fromhex('0x1.0c1524p+0')
    assert memory.word(0x92f078) == 0xe3a02445  # far bits 0x45000000 = 2048
    assert memory.word(0x92f08c) == 0xe3a035fe  # near bits 0x3f800000 = 1
    result = dict(elf_sha256=hashlib.sha256(memory.data).hexdigest(), verified_words=count,
                  callback_code=[hex(START),'0x92f150'], helper_code=['0x92f170','0x92f294'],
                  fields=fields, vfp_constants=constants, literals=literals,
                  helper_abi=dict(r0='64-byte output',r1='angle float bits',r2='lane0/lane1 float bits',
                                  r3='near=1.0 bits',stack0='far=2048.0 bits'),
                  matrix_indices={'0':'cot/aspect','5':'cot','10':'(far+near)/(near-far)',
                                  '11':'-1','14':'((2*far)*near)/(near-far)','others':'+0'},
                  window_semantics='lane0/lane1 only; width/height names and units not proved',
                  boundary='Static full-body recovery plus local C++ reference tests; no original-runtime differential or GLES consumer proof')
    return text, result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf',type=Path)
    args = parser.parse_args()
    text, result = recover(args.elf)
    (NATIVE/'disasm_projection_update.txt').write_text(text)
    (NATIVE/'projection_update.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__ == '__main__':
    main()
