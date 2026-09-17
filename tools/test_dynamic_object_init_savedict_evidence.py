#!/usr/bin/env python3
import json
from pathlib import Path
NATIVE=Path(__file__).resolve().parents[1]/'reconstruction/reverse-v3/native'
def main():
 r=json.loads((NATIVE/'dynamicobject_init_savedict.json').read_text())
 assert r['method']=='DynamicObject -[initWithWorld:dynamicWorld:saveDict:cache:]'
 assert r['imp']=='0x00839f7c' and r['boundary_end']=='0x0083a3c0'
 assert r['code_words']==251 and r['coverage_words']==273
 assert r['pic_base']=='0x0105faf4'
 assert r['dispatch_imports']==['objc_msgSendSuper2','objc_msgSend']
 assert r['known_selectors']['objectForKey:']=='0x0083a388'
 assert r['known_selectors']['floatValue']=='0x0083a37c'
 assert r['known_selectors']['intValue']=='0x0083a394'
 assert r['known_selectors']['unsignedLongValue']=='0x0083a3b4'
 assert r['arguments']['saveDict']=='[fp+8] stored at [fp-0x30]'
 assert r['arguments']['cache']=='[fp+12] stored at [fp-0x34]'
 print('dynamicobject-init-savedict-evidence: PASS')
if __name__=='__main__':main()
