from __future__ import annotations
import subprocess
from pathlib import Path
def run_command(argv,cwd=None,timeout=60):
    if not argv or not all(isinstance(x,str) and x for x in argv):return {"status":"UNVERIFIED","reason":"invalid argv"}
    try:
        cp=subprocess.run(argv,cwd=str(cwd) if cwd else None,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout,shell=False);return {"status":"PASS" if cp.returncode==0 else "FAIL","returncode":cp.returncode,"output":cp.stdout[-4000:]}
    except subprocess.TimeoutExpired as exc:return {"status":"FAIL","reason":"timeout","output":(exc.stdout or "")[-1000:] if isinstance(exc.stdout,str) else ""}
    except OSError as exc:return {"status":"UNVERIFIED","reason":f"{type(exc).__name__}: {exc}"}
