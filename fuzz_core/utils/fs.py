from pathlib import Path
import shutil

def ensure_dir(path: str|Path) -> Path:
    p=Path(path); p.mkdir(parents=True, exist_ok=True); return p

def copytree_clean(src: str|Path, dst: str|Path):
    src=Path(src); dst=Path(dst)
    if dst.exists(): shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".fuzz_core_generated"))
    return dst
