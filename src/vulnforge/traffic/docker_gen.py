import json
from pathlib import Path


def generate_bundle(name: str, module_path: Path, out_dir: str | Path) -> Path:
    target = Path(out_dir) / name
    target.mkdir(parents=True, exist_ok=True)
    module = str(module_path)
    command = ["python", *module.split()] if module.startswith("-m ") else ["python", module]
    (target / "Dockerfile").write_text(
        "FROM python:3.11-slim\nWORKDIR /app\nCOPY . /app\nRUN pip install --no-cache-dir .\n"
        f"ENTRYPOINT {json.dumps(command)}\n", encoding="utf-8"
    )
    (target / "entrypoint.sh").write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
    dockerfile_from_context = target.relative_to(target.parents[2]) / "Dockerfile"
    (target / "docker-compose.yml").write_text(
        "services:\n  attack:\n    build:\n      context: ../../..\n"
        f"      dockerfile: {dockerfile_from_context.as_posix()}\n    network_mode: host\n",
        encoding="utf-8"
    )
    return target
