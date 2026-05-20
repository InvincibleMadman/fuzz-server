from pathlib import Path
def parse_fuzzer_stats(path: str):
    p=Path(path)
    out={}
    if p.exists():
        for line in p.read_text(errors="ignore").splitlines():
            if ":" in line:
                k,v=[x.strip() for x in line.split(":",1)]
                out[k]=v
    return out
