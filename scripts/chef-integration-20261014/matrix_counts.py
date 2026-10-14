#!/usr/bin/env python3
"""Observe the failing original ordinal assertion; acceptance remains unchanged."""
import hashlib
import json
from pathlib import Path
import sys
import types

fixture = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0,str(fixture.parent))
path = fixture.with_name('g7_fault_matrix.py')
source = path.read_text()
anchor = '                    assert summary(current) == control[2], "fault ordinal did not reach the positive logical boundary"'
assert source.count(anchor)==1
diagnostic = '                    print("CHEF_BOUNDARY_COUNTS " + json.dumps(dict(index=last, phase=phase, current=summary(current), control=control[2]), sort_keys=True), flush=True)\n'
instrumented=source.replace(anchor,diagnostic+anchor)
print('CHEF_MATRIX_PROVENANCE '+json.dumps(dict(original_sha256=hashlib.sha256(source.encode()).hexdigest(),
    instrumented_sha256=hashlib.sha256(instrumented.encode()).hexdigest(),assertion='unchanged')),flush=True)
module=types.ModuleType('g7_fault_matrix')
module.__file__=str(path)
sys.modules[module.__name__]=module
exec(compile(instrumented,str(path),'exec'),module.__dict__)
sys.argv=sys.argv[1:]
exec(compile(fixture.read_text(),str(fixture),'exec'),{'__file__':str(fixture),'__name__':'__main__'})
