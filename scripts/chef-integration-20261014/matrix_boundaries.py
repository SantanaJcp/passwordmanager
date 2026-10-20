#!/usr/bin/env python3
"""One run per original boundary/error; retain each original assertion and RED.

An early fixture assertion must not hide later boundaries. This additional
probe does not replace the original matrix's failing exit status.
"""
import json
from pathlib import Path
import sys

fixture = Path(sys.argv[1]).resolve(strict=True)
binary, cli, interposer = map(lambda p:Path(p).resolve(strict=True),sys.argv[2:5])
output = Path(sys.argv[5]).resolve()
sys.path.insert(0,str(fixture.parent))
import g7_fault_matrix as matrix
controls=[]
matrix.run_case(binary,cli,interposer,False,lambda f:controls.extend(matrix.exercise(f,trace=True)))
assert controls, 'positive syscall control absent'
rows=[]
for logical in ['wal','staging','commit-outbox-audit','audit']:
    control=next(row for row in controls if row[1]==logical)
    for error in ['EIO','ENOSPC']:
        row=dict(logical=logical,index=control[0],error=error,status='running')
        try:
            matrix.run_case(binary,cli,interposer,False,
                lambda f:matrix.exercise(f,selected=control[0],control=control,error=error))
            row['status']='PASS'
        except BaseException as failure:
            row['status']='RED' if isinstance(failure,matrix.ProductRed) else 'FIXTURE_ERROR'
            row['error_type']=type(failure).__name__
            row['message']=str(failure)
        rows.append(row)
        output.write_text(json.dumps(rows,indent=2)+'\n')
        print('CHEF_BOUNDARY_RESULT '+json.dumps(row,sort_keys=True),flush=True)
raise SystemExit(1 if any(row['status']!='PASS' for row in rows) else 0)
