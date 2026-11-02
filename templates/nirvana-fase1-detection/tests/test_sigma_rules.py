import json
from pathlib import Path
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections" / "linux"
EVENTS_DIR = ROOT / "tests" / "events"

def _match_selection(sel, event):
    for field, value in sel.items():
        op = None
        if "|" in field:
            field, op = field.split("|", 1)
        ev = event.get(field)
        if ev is None:
            return False
        if op == "endswith":
            if not str(ev).endswith(value): return False
        elif op == "startswith":
            if not str(ev).startswith(value): return False
        elif op == "contains":
            vals = value if isinstance(value, list) else [value]
            if not any(v in str(ev) for v in vals): return False
        else:
            if ev != value: return False
    return True

def _evaluate(rule, event):
    det = rule["detection"]
    results = {k: _match_selection(v, event) for k, v in det.items() if k != "condition"}
    tokens = det["condition"].replace("(", " ").replace(")", " ").split()
    result, op = None, None
    for tok in tokens:
        if tok in ("and", "or"):
            op = tok
        else:
            val = results.get(tok, False)
            result = val if result is None else (
                result and val if op == "and" else result or val
            )
    return bool(result)

def _load_events(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

def _cases():
    out = []
    for rf in sorted(RULES_DIR.glob("*.yml")):
        rule = yaml.safe_load(rf.read_text(encoding="utf-8"))
        ef = EVENTS_DIR / f"{rf.stem}.jsonl"
        if not ef.exists(): continue
        for i, ev in enumerate(_load_events(ef)):
            out.append(pytest.param(rule, ev, id=f"{rf.stem}[{i}]"))
    return out

@pytest.mark.parametrize("rule,event", _cases())
def test_rule_match(rule, event):
    expected = event.pop("_match")
    assert _evaluate(rule, event) is expected