#!/usr/bin/env python3
"""Independent O0/O2 Release assertions, mutation checks; no shared build edits."""
import argparse,json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'reconstruction/recovered'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--results',type=Path)
args=parser.parse_args()
compiler=os.environ.get('CXX','clang++')
implementation=(SRC/'gameview_input.cpp').read_text()
results=[]
with tempfile.TemporaryDirectory(prefix='gameview_input_') as td:
 t=Path(td)
 dependencies=[str(SRC/n) for n in ('gameview_update.cpp','pinch_return.cpp','translation_return.cpp','zoom_settle.cpp','projection_update.cpp')]
 common=[compiler,'-std=c++17','-DNDEBUG','-UNDEBUG','-ffp-contract=off','-fno-fast-math','-I'+str(SRC),str(SRC/'gameview_input_test.cpp')]
 for opt in ('-O0','-O2'):
  output=t/('test'+opt)
  command=common+[opt,str(SRC/'gameview_input.cpp')]+dependencies+['-o',str(output)]
  subprocess.run(command,check=True)
  run=subprocess.run([str(output)],capture_output=True,text=True,check=True)
  results.append(dict(configuration='Release'+opt,command=command,stdout=run.stdout))
 # These are explicit test-sensitivity mutations, not a claimed historical RED.
 for name,old,new in [('doubletap_boundary','self.pinchScale > 3.0','self.pinchScale >= 3.0'),('gesture_end','if (state==3 || state==4) s.pinching=false;','if (state==3) s.pinching=false;'),('gesture_offset','0.025f);','0.05f);'),('gesture_velocity','velocity<100.0f','velocity<=100.0f')]:
  assert implementation.count(old)==1
  mutant=t/(name+'.cpp'); mutant.write_text(implementation.replace(old,new))
  output=t/name
  subprocess.run(common+['-O2',str(mutant)]+dependencies+['-o',str(output)],check=True)
  run=subprocess.run([str(output)],capture_output=True,text=True)
  assert run.returncode!=0 and 'assert' in run.stderr.lower(),(name,run.returncode,run.stderr)
  results.append(dict(mutation=name,expected_failure=True,returncode=run.returncode,stderr=run.stderr))
 # Compile-time failure proves an accidental retained NDEBUG is rejected.
 run=subprocess.run([compiler,'-std=c++17','-DNDEBUG','-I'+str(SRC),'-fsyntax-only',str(SRC/'gameview_input_test.cpp')],capture_output=True,text=True)
 assert run.returncode!=0 and 'Assertions MUST stay enabled' in run.stderr
 results.append(dict(ndebug_negative_check='PASS',stderr=run.stderr))
if args.results: args.results.write_text(json.dumps(results,indent=2)+'\n')
print('PASS: Release -O0/-O2, assertions enabled; 4 behavioral mutants rejected; NDEBUG-only rejected')
