"""Save scan observations exclusively under MCP/results/.

Never writes anywhere outside this directory. Independent of (and does not
touch) the parent workshop's own results/ folder.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

RESULTS_ROOT = Path(__file__).resolve().parent.parent / "results"


def new_run_dir(prefix: str) -> Path:
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    # Windows wall-clock readings can repeat even with microsecond formatting.
    run_dir = RESULTS_ROOT / f"{prefix}-{stamp}-{uuid4().hex[:12]}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def save_json(run_dir: Path, name: str, data: Any) -> Path:
    path = run_dir / name
    path.write_text(json.dumps(data, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
    return path


COLLECTIONS = ('records', 'packets', 'events', 'devices', 'services', 'rssi_dbm')
RAW_FIELDS = ('raw_text', 'raw_control_text')


def page_bounds(offset, limit):
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError('offset must be nonnegative; limit must be an integer from 1 through 200.')


def observation_page(data: dict, offset=0, limit=50, field=None) -> dict:
    """Bound MCP replies while keeping complete observations on disk."""
    page_bounds(offset, limit)
    if field is not None and (field not in COLLECTIONS or not isinstance(data.get(field), list)):
        raise ValueError('field must name an available records/packets/events/devices/services/rssi_dbm array.')
    result = {k: v for k, v in data.items() if k not in RAW_FIELDS and k not in COLLECTIONS}
    result['pagination'] = {}
    rssi = data.get('rssi_dbm')
    if isinstance(rssi, list):
        valid = [v for v in rssi if isinstance(v, (int, float)) and not isinstance(v, bool)]
        result['rssi_summary'] = dict(count=len(valid), minimum=min(valid) if valid else None,
                                      maximum=max(valid) if valid else None,
                                      average=sum(valid) / len(valid) if valid else None)
    for key in COLLECTIONS:
        values = data.get(key)
        if not isinstance(values, list) or field is not None and key != field:
            continue
        result[key] = values[offset:offset + limit]
        result['pagination'][key] = dict(total=len(values), offset=offset, returned=len(result[key]),
                                         next_offset=offset + limit if offset + limit < len(values) else None)
    raw = {key: len(data[key]) for key in RAW_FIELDS if isinstance(data.get(key), str)}
    if raw:
        result['raw_fields_saved_not_inlined'] = raw
    if 'packets' in data:
        result['packet_count'] = len(data['packets'])
    if 'records' in data:
        result['record_count'] = len(data['records'])
    if 'events' in data:
        result['event_count'] = len(data['events'])
    return result


def list_runs(limit=20, offset=0) -> dict[str, Any]:
    page_bounds(offset, limit)
    if not RESULTS_ROOT.is_dir():
        return dict(runs=[], total=0, offset=offset, limit=limit, next_offset=None)
    runs = []
    for entry in sorted(RESULTS_ROOT.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        if RESULTS_ROOT.resolve() not in entry.resolve().parents:
            continue
        runs.append(entry)
    rows = []
    for entry in runs[offset:offset + limit]:
        observation_path = entry / 'observation.json'
        row = dict(name=entry.name, modified_unix=entry.stat().st_mtime,
                   has_observation=observation_path.exists())
        if observation_path.exists():
            try:
                data = load_observation(entry.name)
                row['status'] = data.get('status', 'not_reported')
                row['counts'] = {key: len(data[key]) for key in COLLECTIONS if isinstance(data.get(key), list)}
            except (OSError, ValueError) as exc:
                row["error"] = f"Could not read observation.json: {exc}"
        rows.append(row)
    return dict(runs=rows, total=len(runs), offset=offset, limit=limit,
                next_offset=offset + limit if offset + limit < len(runs) else None)


def load_observation(run_name: str) -> dict[str, Any]:
    run_dir = (RESULTS_ROOT / run_name).resolve()
    if RESULTS_ROOT.resolve() not in run_dir.parents and run_dir != RESULTS_ROOT.resolve():
        raise ValueError(f"Refusing path outside MCP/results/: {run_name!r}")
    observation_path = (run_dir / "observation.json").resolve()
    if RESULTS_ROOT.resolve() not in observation_path.parents:
        raise ValueError(f'Refusing observation outside MCP/results/: {run_name!r}')
    if not observation_path.exists():
        raise FileNotFoundError(f"No observation.json under {run_dir}")
    return json.loads(observation_path.read_text(encoding="utf-8"))
