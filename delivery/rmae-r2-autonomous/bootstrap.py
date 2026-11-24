#!/usr/bin/env python3
"""Подготовка изолированной source-run среды R2 Autonomous.

Скрипт читает только встроенный архив рядом с собой. Сеть, старая venv и PATH
не используются. Научную приёмку не ставит.
"""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True

COMMIT = "fef168622d9ffa1d7f8f9ebb241b6932659d62aa"
RUNTIME_NAME = "RMAE_R2_OFFLINE_RUNTIME.zip"
RUNTIME_SHA256 = "f0d0bfba47026ea033ffdffdf76d4a4fe10946ec955ac616d4731e6d28693bf4"
RUNTIME_BYTES = 5479858
INNER_NAME = "RMAE_R2_CLI_RUNTIME_BUNDLE.zip"
INNER_SHA256 = "3718219490c52357e6bf9bb2564cd46dbf9252b7b9844ad6122f2d2393b232bb"
DECLARED_VERSION = "2.10.1"
PROTOCOL_VERSION = "1.0.0"
SOURCE_FILE_COUNT = 45
WHEEL_COUNT = 10
MAX_MEMBER = 40 * 1024 * 1024
MAX_ARCHIVE = 80 * 1024 * 1024
SMOKE_TEXT = "В исследование включили 48 пациентов. После операции наблюдение продолжалось 30 суток."
IMPORTS = {
    "annotated-types": "annotated_types",
    "markdown-it-py": "markdown_it",
    "mdurl": "mdurl",
    "pydantic": "pydantic",
    "pydantic-core": "pydantic_core",
    "pygments": "pygments",
    "regex": "regex",
    "rich": "rich",
    "typing-extensions": "typing_extensions",
    "typing-inspection": "typing_inspection",
}
FROZEN = {
    "LICENSE": "ad1103ff13b0d8824dbd44bee43009c0285684e955ca0839f8d8d9b99c1b4ca5",
    "NOTICE.md": "f660d669d6f91ae33902b11697083941c4a8b3a46343a61101f6ac20c9aedc69",
    "checks.py": "e452be6d0877acb53e60720ea7aa547963769c3fa5aa2d5bd279c9794a264ee9",
    "references/decisions-and-examples.md": "e2477e932f83193a8ee98149086fdbac6e99f97d5c946b586cf2adcb5026e5b9",
    "references/medical-invariants.md": "d7d91cee68758d5d897bafe5577ab1a1364bb01650b40bbfecf840fd95f86919",
}
OBSOLETE = (
    "Архив навыка среду Python не содержит",
    "Архив навыка эту команду не содержит",
)
TAG_RE = re.compile(r"^(?:py3-none-any|cp312-cp312-(?:manylinux2014_x86_64|manylinux_2_(?:17|28)_x86_64))$")
PROVENANCE = r"""
import importlib, importlib.metadata as meta, json, sys
from pathlib import Path
names = json.loads(sys.argv[1])
import aiw_ru
found = {}
for dist, module in names.items():
    mod = importlib.import_module(module)
    found[dist] = {"version": meta.version(dist), "module": mod.__file__}
installed = sorted(item.metadata["Name"] for item in meta.distributions())
print(json.dumps({
    "python": sys.version,
    "prefix": sys.prefix,
    "aiw_ru_file": aiw_ru.__file__,
    "distributions": found,
    "installed_distributions": installed,
    "path": sys.path,
}, ensure_ascii=False))
"""


class GateFailure(Exception):
    def __init__(self, status: str, stage: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.stage = stage
        self.reason = reason


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def norm_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def glibc_version() -> tuple[int, int]:
    raw = os.confstr("CS_GNU_LIBC_VERSION") or ""
    match = re.search(r"(\d+)\.(\d+)", raw)
    if not match:
        raise GateFailure("BLOCKED", "host_platform", f"версия glibc не прочитана: {raw!r}")
    return int(match.group(1)), int(match.group(2))


def reject_zip_name(name: str) -> None:
    if not name or "\\" in name or "\x00" in name:
        raise ValueError(f"небезопасное имя: {name!r}")
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"небезопасный путь: {name}")
    if pure.parts and ":" in pure.parts[0]:
        raise ValueError(f"небезопасный путь: {name}")


def is_symlink_member(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == stat.S_IFLNK


def inspect_zip_bytes(data: bytes) -> zipfile.ZipFile:
    """Проверка структуры ZIP до распаковки. Отказ — ValueError, архив не пишется на диск."""
    if len(data) > MAX_ARCHIVE:
        raise ValueError("архив больше допустимого размера")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        raise ValueError(f"не ZIP: {error}") from error
    names = archive.namelist()
    if len(names) != len(set(names)):
        raise ValueError("повторная запись ZIP")
    total = 0
    for info in archive.infolist():
        reject_zip_name(info.filename)
        if is_symlink_member(info):
            raise ValueError(f"симлинк в ZIP: {info.filename}")
        if info.flag_bits & 0x1:
            raise ValueError(f"шифрованная запись: {info.filename}")
        if info.file_size > MAX_MEMBER:
            raise ValueError(f"запись слишком большая: {info.filename}")
        total += info.file_size
    if total > MAX_ARCHIVE:
        raise ValueError("распакованный объём больше допустимого")
    bad = archive.testzip()
    if bad is not None:
        raise ValueError(f"CRC не сошёлся: {bad}")
    return archive


def zip_files(archive: zipfile.ZipFile) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for info in archive.infolist():
        if info.is_dir() or info.filename.endswith("/"):
            continue
        payload = archive.read(info)
        if len(payload) != info.file_size:
            raise ValueError(f"размер записи не совпал: {info.filename}")
        files[info.filename] = payload
    return files


def manifest_hashes(files: dict[str, bytes]) -> dict[str, str]:
    if "SHA256SUMS.txt" not in files:
        raise ValueError("нет SHA256SUMS.txt")
    entries: dict[str, str] = {}
    for line in files["SHA256SUMS.txt"].decode("utf-8").splitlines():
        if not line.strip():
            continue
        if "  " not in line:
            raise ValueError("битая строка SHA256SUMS")
        digest, name = line.split("  ", 1)
        reject_zip_name(name)
        if name in entries:
            raise ValueError(f"повтор в манифесте: {name}")
        entries[name] = digest
    if set(entries) != set(files) - {"SHA256SUMS.txt"}:
        raise ValueError("список SHA256SUMS не совпал с архивом")
    for name, digest in entries.items():
        if sha256_bytes(files[name]) != digest:
            raise ValueError(f"контрольная сумма не совпала: {name}")
    return entries


def parse_requirements(text: str) -> dict[str, dict[str, object]]:
    chunks: dict[str, dict[str, object]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([\w.-]+)==([^\s\\]+)", line)
        if match:
            current = match.group(1)
            chunks[current] = {"version": match.group(2), "hashes": []}
            continue
        if current and "--hash=sha256:" in line:
            digest = line.split("--hash=sha256:", 1)[1].strip().rstrip("\\").strip()
            hashes = chunks[current]["hashes"]
            assert isinstance(hashes, list)
            hashes.append(digest)
    return chunks


def wheel_supported(tags: list[str], glibc: tuple[int, int]) -> bool:
    for tag in tags:
        if TAG_RE.fullmatch(tag) is None:
            continue
        if tag == "py3-none-any":
            return True
        if "manylinux2014_" in tag:
            need = (2, 17)
        else:
            match = re.search(r"manylinux_2_(\d+)_", tag)
            if match is None:
                continue
            need = (2, int(match.group(1)))
        if glibc >= need:
            return True
    return False


def read_wheel(data: bytes, expected: dict[str, object], glibc: tuple[int, int]) -> dict[str, object]:
    filename = str(expected["filename"])
    if len(data) != expected["size"] or sha256_bytes(data) != expected["sha256"]:
        raise ValueError(f"байты wheel не совпали: {filename}")
    with inspect_zip_bytes(data) as archive:
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        wheels = [name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")]
        if len(metadata) != 1 or len(wheels) != 1:
            raise ValueError(f"метаданные wheel не найдены: {filename}")
        if metadata[0].rsplit("/", 1)[0] != wheels[0].rsplit("/", 1)[0]:
            raise ValueError(f"метаданные wheel из разных каталогов: {filename}")
        meta = email.parser.BytesParser().parsebytes(archive.read(metadata[0]))
        tags = email.parser.BytesParser().parsebytes(archive.read(wheels[0])).get_all("Tag") or []
    if norm_name(meta.get("Name", "")) != norm_name(str(expected["name"])):
        raise ValueError(f"имя wheel не совпало: {filename}")
    if meta.get("Version") != expected["version"]:
        raise ValueError(f"версия wheel не совпала: {filename}")
    if not wheel_supported(tags, glibc):
        raise ValueError(f"wheel не подходит этой платформе: {filename} {tags}")
    return {
        "name": expected["name"],
        "version": expected["version"],
        "filename": filename,
        "sha256": expected["sha256"],
        "bytes": len(data),
        "tags": tags,
    }


def dependency_closure(lock: dict[str, object]) -> dict[str, dict[str, object]]:
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValueError("в lockfile нет package")
    found: dict[str, dict[str, object]] = {}
    for item in packages:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("битая запись lockfile")
        name = item["name"]
        if name in found:
            raise ValueError(f"повтор пакета в lockfile: {name}")
        found[name] = item
    seen: set[str] = set()
    stack = ["aiw-ru"]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        if name not in found:
            raise ValueError(f"в lockfile нет зависимости {name}")
        seen.add(name)
        deps = found[name].get("dependencies", [])
        if not isinstance(deps, list):
            raise ValueError(f"зависимости не списком: {name}")
        for dep in deps:
            if not isinstance(dep, dict) or not isinstance(dep.get("name"), str):
                raise ValueError(f"битая зависимость: {name}")
            stack.append(dep["name"])
    return {name: found[name] for name in seen}


def smoke_problems(scan: object, validate: object, coverage: object) -> str | None:
    """Содержательная проверка smoke. Код выхода 0 сам по себе готовность не даёт."""
    if not isinstance(scan, dict):
        return "scan не объект"
    stats = scan.get("stats")
    if not isinstance(stats, dict):
        return "в scan нет stats"
    if type(stats.get("words")) is not int or stats["words"] <= 0:
        return "stats.words не положительное целое"
    if stats.get("contextMode") != "academic":
        return "contextMode не academic"
    if "classifier" in scan:
        return "в scan есть classifier"
    if type(scan.get("score")) is not int or not isinstance(scan.get("issues"), list):
        return "схема scan неполная"
    meta = scan.get("meta")
    if not isinstance(meta, dict) or "schema" not in meta:
        return "в scan нет meta.schema"
    if not isinstance(validate, dict):
        return "validate не объект"
    if validate.get("ok") is not True:
        return "validate ok не true"
    for key in ("warnings", "violations", "swappedNumbers"):
        if validate.get(key) != []:
            return f"validate.{key} не пустой список"
    validate_meta = validate.get("meta")
    if not isinstance(validate_meta, dict) or "schema" not in validate_meta:
        return "в validate нет meta.schema"
    if not isinstance(coverage, dict):
        return "coverage не объект"
    if coverage.get("disposition") != "COVERED" or coverage.get("full_range_acceptance") is not True:
        return "coverage не COVERED"
    if coverage.get("scientific_acceptance") is True:
        return "helper выставил научную приёмку"
    return None


def _json_text(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def emit(payload: dict[str, object], code: int, logs_dir: Path | None) -> int:
    text = _json_text(payload)
    sys.stdout.write(text)
    if logs_dir is not None:
        logs_dir.mkdir(parents=True, exist_ok=True)
        (logs_dir / "bootstrap.json").write_text(text, encoding="utf-8")
    return code


def failure_payload(error: GateFailure, commands: list[dict[str, object]], logs_dir: Path | None) -> dict[str, object]:
    return {
        "status": error.status,
        "stage": error.stage,
        "reason": error.reason,
        "mode": "source-run",
        "paths_usable": False,
        "raw_report": None,
        "CLI_INSTALL": "NOT_RUN",
        "LOCKED_PROJECT_RUN": "NOT_RUN",
        "scientific_acceptance": "PENDING",
        "commands": commands,
        "logs_dir": str(logs_dir) if logs_dir else None,
    }


def child_env(uv: str, home: Path, cache: Path, pythonpath: str | None = None) -> dict[str, str]:
    path = os.pathsep.join(dict.fromkeys([str(Path(uv).parent), "/usr/bin", "/bin"]))
    env = {
        "PATH": path,
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "UV_PYTHON_DOWNLOADS": "never",
        "UV_OFFLINE": "1",
        "UV_CACHE_DIR": str(cache),
        "UV_LINK_MODE": "copy",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONUTF8": "1",
    }
    if pythonpath is not None:
        env["PYTHONPATH"] = pythonpath
    return env


def run_command(
    name: str,
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    logs: Path,
    commands: list[dict[str, object]],
) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, check=False)
    (logs / f"{name}.stdout").write_bytes(proc.stdout)
    (logs / f"{name}.stderr").write_bytes(proc.stderr)
    (logs / f"{name}.exit").write_text(str(proc.returncode), encoding="utf-8")
    safe_env = {
        key: env[key]
        for key in (
            "UV_OFFLINE",
            "UV_PYTHON_DOWNLOADS",
            "UV_CACHE_DIR",
            "UV_LINK_MODE",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONPATH",
            "PYTHONNOUSERSITE",
            "PYTHONSAFEPATH",
        )
        if key in env
    }
    commands.append(
        {
            "name": name,
            "argv": argv,
            "cwd": str(cwd),
            "env_overrides": safe_env,
            "exit_code": proc.returncode,
            "stdout_file": str(logs / f"{name}.stdout"),
            "stderr_file": str(logs / f"{name}.stderr"),
        }
    )
    return proc


def networked_output(data: bytes) -> bool:
    text = data.decode("utf-8", errors="replace").lower()
    markers = ("downloading", "files.pythonhosted.org", "pypi.org", "pypi.python.org")
    return any(marker in text for marker in markers)


def load_json_stdout(proc: subprocess.CompletedProcess[bytes], stage: str) -> object:
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateFailure("FAIL", stage, f"stdout не JSON: {error}") from error


def assert_inside(root: Path, path: Path) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise GateFailure("BLOCKED", "extract", f"путь вышел из каталога: {path}")
    return resolved


def safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for info in archive.infolist():
        reject_zip_name(info.filename)
        if is_symlink_member(info):
            raise GateFailure("BLOCKED", "extract", f"симлинк: {info.filename}")
        target = destination / info.filename
        parent = assert_inside(destination, target.parent)
        if info.is_dir() or info.filename.endswith("/"):
            parent.mkdir(parents=True, exist_ok=True)
            continue
        parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(target, flags, 0o644)
        except FileExistsError as error:
            raise GateFailure("BLOCKED", "extract", f"файл уже есть: {info.filename}") from error
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(archive.read(info))
        except Exception:
            os.unlink(target)
            raise
        written = target.stat().st_size
        if written != info.file_size:
            raise GateFailure("BLOCKED", "extract", f"размер после записи не совпал: {info.filename}")


def host_gate() -> tuple[str, tuple[int, int], str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise GateFailure("BLOCKED", "host_root", "запуск от root запрещён")
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 12):
        raise GateFailure(
            "BLOCKED",
            "host_python",
            f"нужен CPython 3.12, найден {sys.implementation.name} {sys.version.split()[0]}",
        )
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        found = f"{platform.system()} {platform.machine()}"
        raise GateFailure("BLOCKED", "host_platform", f"нужен Linux x86_64, найдено {found}")
    glibc = glibc_version()
    if glibc < (2, 28):
        raise GateFailure("BLOCKED", "host_platform", f"glibc {glibc[0]}.{glibc[1]} старше, чем manylinux_2_28")
    uv = shutil_which("uv")
    if uv is None:
        raise GateFailure("BLOCKED", "host_uv", "uv не найден; скачивание и установка uv не выполняются")
    return uv, glibc, platform.platform()


def shutil_which(name: str) -> str | None:
    import shutil

    found = shutil.which(name)
    if found is None:
        return None
    return str(Path(found).resolve())


def check_documents(skill: Path) -> None:
    skill_md = (skill / "SKILL.md").read_text(encoding="utf-8")
    runtime_md = (skill / "references" / "runtime-and-artifacts.md").read_text(encoding="utf-8")
    for label, text in (("SKILL.md", skill_md), ("runtime-and-artifacts.md", runtime_md)):
        for old in OBSOLETE:
            if old in text:
                raise GateFailure("BLOCKED", "instructions", f"{label} содержит устаревшее указание: {old}")
        for needle in (
            "R2 Autonomous",
            "runtime/bootstrap.py",
            'PYTHONPATH="$VERIFIED_SRC"',
            "-m aiw_ru scan",
            'aiw-ru scan "$INPUT" --context vak --no-model --json',
            'aiw-ru validate "$ORIGINAL" "$CLEAN" --context vak --json',
        ):
            if needle not in text:
                raise GateFailure("BLOCKED", "instructions", f"{label} не содержит {needle}")
    for needle in (
        "name: russian-medical-academic-editor",
        "version: 2.10.1",
        'protocol_version: "1.0.0"',
        "license: MIT",
        'packaging_revision: "R2-autonomous"',
    ):
        if needle not in skill_md:
            raise GateFailure("BLOCKED", "instructions", f"SKILL.md не содержит {needle}")
    for relative, digest in FROZEN.items():
        path = skill / relative
        data = path.read_bytes()
        if sha256_bytes(data) != digest:
            raise GateFailure("BLOCKED", "skill_files", f"хэш {relative} не равен R2")


def verify_runtime_bytes(data: bytes, glibc: tuple[int, int]) -> dict[str, object]:
    if len(data) != RUNTIME_BYTES or sha256_bytes(data) != RUNTIME_SHA256:
        raise GateFailure(
            "BLOCKED",
            "runtime_hash",
            f"встроенный архив: {len(data)} байт, sha256 {sha256_bytes(data)}",
        )
    try:
        outer = inspect_zip_bytes(data)
    except ValueError as error:
        raise GateFailure("BLOCKED", "runtime_structure", str(error)) from error
    with outer:
        try:
            files = zip_files(outer)
            manifest_hashes(files)
        except ValueError as error:
            raise GateFailure("BLOCKED", "runtime_structure", str(error)) from error
    wheel_manifest = json.loads(files["WHEEL_MANIFEST.json"].decode("utf-8"))
    wheels = wheel_manifest.get("wheels")
    if not isinstance(wheels, list) or len(wheels) != WHEEL_COUNT:
        raise GateFailure("BLOCKED", "runtime_manifest", "в манифесте не десять wheel")
    if wheel_manifest.get("commit") != COMMIT:
        raise GateFailure("BLOCKED", "runtime_manifest", "commit манифеста wheel не равен R2")
    expected = {
        "00_READ_FIRST.md",
        "SHA256SUMS.txt",
        "WHEEL_MANIFEST.json",
        INNER_NAME,
        *{f"wheelhouse/{item['filename']}" for item in wheels},
    }
    if set(files) != expected:
        raise GateFailure("BLOCKED", "runtime_structure", "состав внешнего архива не совпал")
    inner = files[INNER_NAME]
    if sha256_bytes(inner) != INNER_SHA256 or wheel_manifest.get("source_archive_sha256") != INNER_SHA256:
        raise GateFailure("BLOCKED", "runtime_manifest", "хэш внутреннего архива не совпал")
    try:
        inner_zip = inspect_zip_bytes(inner)
    except ValueError as error:
        raise GateFailure("BLOCKED", "runtime_structure", f"внутренний архив: {error}") from error
    with inner_zip:
        try:
            inner_files = zip_files(inner_zip)
            manifest_hashes(inner_files)
        except ValueError as error:
            raise GateFailure("BLOCKED", "runtime_structure", f"внутренний архив: {error}") from error
    source_manifest = json.loads(inner_files["SOURCE_MANIFEST.json"].decode("utf-8"))
    if source_manifest.get("commit") != COMMIT or len(source_manifest.get("files", [])) != SOURCE_FILE_COUNT:
        raise GateFailure("BLOCKED", "runtime_manifest", "манифест исходников не совпал с R2")
    source_paths = set()
    for item in source_manifest["files"]:
        path = item["path"]
        reject_zip_name(path)
        blob = inner_files.get(path)
        identity_ok = (
            blob is not None
            and len(blob) == item["bytes"]
            and sha256_bytes(blob) == item["sha256"]
            and git_blob(blob) == item["git_blob_sha1"]
        )
        if not identity_ok:
            raise GateFailure("BLOCKED", "runtime_manifest", f"исходник не совпал: {path}")
        source_paths.add(path)
    zipped_sources = {name for name in inner_files if name.startswith("source/") and not name.endswith("/")}
    if source_paths != zipped_sources:
        raise GateFailure("BLOCKED", "runtime_manifest", "список source/ не совпал с манифестом")
    requirements = parse_requirements(inner_files["requirements-runtime-lock.txt"].decode("utf-8"))
    try:
        locked = dependency_closure(tomllib.loads(inner_files["source/uv.lock"].decode("utf-8")))
    except ValueError as error:
        raise GateFailure("BLOCKED", "runtime_manifest", str(error)) from error
    names = {item["name"] for item in wheels}
    if names != set(IMPORTS) or set(requirements) != names or set(locked) - {"aiw-ru"} != names:
        raise GateFailure("BLOCKED", "runtime_manifest", "замыкание зависимостей не равно десяти пакетам")
    described = []
    for item in wheels:
        filename = item["filename"]
        if PurePosixPath(filename).name != filename:
            raise GateFailure("BLOCKED", "runtime_manifest", f"имя wheel небезопасно: {filename}")
        package = locked[item["name"]]
        hashes = requirements[item["name"]]["hashes"]
        assert isinstance(hashes, list)
        if package["version"] != item["version"] or requirements[item["name"]]["version"] != item["version"]:
            raise GateFailure("BLOCKED", "runtime_manifest", f"версия не совпала: {item['name']}")
        if item["sha256"] not in hashes:
            raise GateFailure("BLOCKED", "runtime_manifest", f"хэш отсутствует в requirements: {item['name']}")
        listed = package.get("wheels", [])
        if not any(
            isinstance(row, dict)
            and row.get("url") == item["url"]
            and row.get("hash") == "sha256:" + item["sha256"]
            and row.get("size") == item["size"]
            for row in listed
        ):
            raise GateFailure("BLOCKED", "runtime_manifest", f"wheel нет в исходном lockfile: {item['name']}")
        try:
            described.append(read_wheel(files[f"wheelhouse/{filename}"], item, glibc))
        except ValueError as error:
            raise GateFailure("BLOCKED", "runtime_manifest", str(error)) from error
    project = tomllib.loads(inner_files["source/pyproject.toml"].decode("utf-8"))
    if project.get("project", {}).get("version") != DECLARED_VERSION:
        raise GateFailure("BLOCKED", "runtime_manifest", "заявленная версия проекта не 2.10.1")
    return {
        "files": files,
        "inner_files": inner_files,
        "wheels": described,
        "declared_version": DECLARED_VERSION,
        "dependency_lock": source_manifest.get("dependency_lock"),
    }


def prepare(
    argv: list[str] | None,
    commands: list[dict[str, object]],
    state: dict[str, Path | None],
) -> dict[str, object]:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--logs-dir", type=Path)

    def parser_error(message: str) -> None:
        raise GateFailure("BLOCKED", "arguments", message)

    parser.error = parser_error  # type: ignore[method-assign]
    args = parser.parse_args(argv)
    skill = Path(__file__).resolve().parent.parent
    runtime_path = Path(__file__).resolve().parent / RUNTIME_NAME
    checks_py = skill / "checks.py"
    check_documents(skill)
    if not runtime_path.is_file():
        raise GateFailure("BLOCKED", "runtime_missing", "встроенный архив не найден рядом со скриптом")
    watched = [runtime_path, checks_py, skill / "SKILL.md", skill / "references" / "runtime-and-artifacts.md"]
    watched.extend(skill / relative for relative in FROZEN)
    before = {str(path.resolve()): sha256_bytes(path.read_bytes()) for path in watched}
    uv, glibc, platform_line = host_gate()
    runtime_bytes = runtime_path.read_bytes()
    verified = verify_runtime_bytes(runtime_bytes, glibc)
    temp_parent = Path(tempfile.gettempdir()).resolve()
    if temp_parent.is_relative_to(skill):
        raise GateFailure("BLOCKED", "host_temp", "временный каталог оказался внутри навыка")
    if args.logs_dir is not None:
        logs_dir = args.logs_dir.expanduser().resolve()
        if logs_dir.is_relative_to(skill):
            raise GateFailure("BLOCKED", "arguments", "каталог журналов внутри навыка")
        logs_dir.mkdir(parents=True, exist_ok=True)
    else:
        logs_dir = None
    work = Path(tempfile.mkdtemp(prefix="rmae-r2-autonomous-"))
    assert_inside(temp_parent, work)
    if logs_dir is None:
        logs_dir = work / "logs"
        logs_dir.mkdir()
    state["logs_dir"] = logs_dir
    home = work / "home"
    cache = work / "empty-uv-cache"
    home.mkdir()
    cache.mkdir()
    outer_dir = work / "runtime"
    inner_dir = work / "source-bundle"
    with zipfile.ZipFile(io.BytesIO(runtime_bytes)) as outer_zip:
        safe_extract(outer_zip, outer_dir)
    inner_bytes = (outer_dir / INNER_NAME).read_bytes()
    if sha256_bytes(inner_bytes) != INNER_SHA256:
        raise GateFailure("FAIL", "extract", "внутренний архив на диске не совпал")
    with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner_zip:
        safe_extract(inner_zip, inner_dir)
    source_src = (inner_dir / "source" / "src").resolve()
    requirements = (inner_dir / "requirements-runtime-lock.txt").resolve()
    wheelhouse = (outer_dir / "wheelhouse").resolve()
    env_dir = work / "venv"
    env = child_env(uv, home, cache)
    base = env
    py = env_dir / "bin" / "python"
    venv_proc = run_command(
        "venv",
        [uv, "venv", "--offline", "--python", sys.executable, str(env_dir)],
        work,
        base,
        logs_dir,
        commands,
    )
    if venv_proc.returncode != 0 or networked_output(venv_proc.stderr):
        raise GateFailure("FAIL", "venv", "uv venv не создал изолированную среду без сети")
    install = run_command(
        "install",
        [
            uv,
            "pip",
            "install",
            "--offline",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--python",
            str(py),
            "--require-hashes",
            "--only-binary",
            ":all:",
            "-r",
            str(requirements),
        ],
        work,
        base,
        logs_dir,
        commands,
    )
    if install.returncode != 0 or networked_output(install.stdout + install.stderr):
        raise GateFailure("FAIL", "install", "офлайн-установка десяти зависимостей не выполнена")
    checked = run_command("pip_check", [uv, "pip", "check", "--python", str(py)], work, base, logs_dir, commands)
    if checked.returncode != 0:
        raise GateFailure("FAIL", "pip_check", "uv pip check не прошёл")
    cfg = (env_dir / "pyvenv.cfg").read_text(encoding="utf-8")
    if re.search(r"(?i)include-system-site-packages\s*=\s*false", cfg) is None:
        raise GateFailure("FAIL", "provenance", "venv не изолирована от системных пакетов")
    with_path = child_env(uv, home, cache, str(source_src))
    provenance_proc = run_command(
        "provenance",
        [str(py), "-c", PROVENANCE, json.dumps(IMPORTS, ensure_ascii=False)],
        work,
        with_path,
        logs_dir,
        commands,
    )
    if provenance_proc.returncode != 0:
        raise GateFailure("FAIL", "provenance", "не удалось прочитать происхождение модулей")
    provenance = load_json_stdout(provenance_proc, "provenance")
    if not isinstance(provenance, dict):
        raise GateFailure("FAIL", "provenance", "provenance не объект")
    aiw_file = Path(str(provenance.get("aiw_ru_file", ""))).resolve()
    if not aiw_file.is_relative_to(source_src):
        raise GateFailure("FAIL", "provenance", "aiw_ru импортирован не из проверенных исходников")
    distributions = provenance.get("distributions")
    if not isinstance(distributions, dict) or set(distributions) != set(IMPORTS):
        raise GateFailure("FAIL", "provenance", "набор зависимостей не равен десяти пакетам")
    for name, row in distributions.items():
        expected_version = next(item["version"] for item in verified["wheels"] if item["name"] == name)
        if not isinstance(row, dict) or row.get("version") != expected_version:
            raise GateFailure("FAIL", "provenance", f"версия {name} не равна lockfile")
        module = Path(str(row.get("module", ""))).resolve()
        if not module.is_relative_to(env_dir.resolve()):
            raise GateFailure("FAIL", "provenance", f"модуль {name} лежит вне новой venv")
    installed = provenance.get("installed_distributions")
    installed_names = {norm_name(str(item)) for item in installed} if isinstance(installed, list) else set()
    if installed_names != {norm_name(name) for name in IMPORTS}:
        raise GateFailure("FAIL", "provenance", "в venv есть лишние или недостающие дистрибутивы")
    version_proc = run_command(
        "cli_version",
        [str(py), "-m", "aiw_ru", "--version"],
        work,
        with_path,
        logs_dir,
        commands,
    )
    reported = version_proc.stdout.decode("utf-8", errors="replace").strip()
    if version_proc.returncode != 0 or reported != "aiw-ru 0.0.0":
        raise GateFailure("FAIL", "cli_version", f"ожидался source-run aiw-ru 0.0.0, получено {reported!r}")
    smoke = work / "smoke"
    smoke.mkdir()
    original = smoke / "original.md"
    copy = smoke / "copy.md"
    payload = SMOKE_TEXT.encode("utf-8")
    original.write_bytes(payload)
    copy.write_bytes(original.read_bytes())
    scan_proc = run_command(
        "scan",
        [str(py), "-m", "aiw_ru", "scan", str(original), "--context", "vak", "--no-model", "--json"],
        work,
        with_path,
        logs_dir,
        commands,
    )
    validate_proc = run_command(
        "validate",
        [str(py), "-m", "aiw_ru", "validate", str(original), str(copy), "--context", "vak", "--json"],
        work,
        with_path,
        logs_dir,
        commands,
    )
    if scan_proc.returncode != 0:
        raise GateFailure("FAIL", "smoke_scan", "scan технического текста завершился ненулевым кодом")
    if validate_proc.returncode != 0:
        raise GateFailure("FAIL", "smoke_validate", "validate точной копии завершился ненулевым кодом")
    scan_obj = load_json_stdout(scan_proc, "smoke_scan")
    validate_obj = load_json_stdout(validate_proc, "smoke_validate")
    helper_env = child_env(uv, home, cache)
    coverage_proc = run_command(
        "coverage",
        [
            sys.executable,
            str(checks_py),
            "coverage",
            "--source",
            str(original),
            "--scan-stdout",
            str(logs_dir / "scan.stdout"),
            "--exit-code",
            "0",
        ],
        work,
        helper_env,
        logs_dir,
        commands,
    )
    sha_proc = run_command(
        "helper_sha256",
        [sys.executable, str(checks_py), "sha256", str(original)],
        work,
        helper_env,
        logs_dir,
        commands,
    )
    if coverage_proc.returncode != 0 or sha_proc.returncode != 0:
        raise GateFailure("FAIL", "helper", "установленный checks.py не выполнил smoke-сверку")
    coverage_obj = load_json_stdout(coverage_proc, "helper")
    sha_obj = load_json_stdout(sha_proc, "helper")
    problem = smoke_problems(scan_obj, validate_obj, coverage_obj)
    if problem:
        raise GateFailure("FAIL", "smoke_schema", problem)
    if not isinstance(sha_obj, dict) or sha_obj.get("sha256") != sha256_bytes(payload):
        raise GateFailure("FAIL", "helper", "хэш checks.py не совпал с байтами smoke-файла")
    read_proc = run_command(
        "read_back",
        [sys.executable, str(checks_py), "read-back", "--file", str(original), "--sha256", str(sha_obj["sha256"])],
        work,
        helper_env,
        logs_dir,
        commands,
    )
    read_obj = load_json_stdout(read_proc, "helper")
    if read_proc.returncode != 0 or not isinstance(read_obj, dict) or read_obj.get("matches") is not True:
        raise GateFailure("FAIL", "helper", "read-back установленного checks.py не совпал")
    if read_obj.get("scientific_acceptance") is True:
        raise GateFailure("FAIL", "helper", "helper выставил научную приёмку")
    if original.read_bytes() != payload or copy.read_bytes() != payload:
        raise GateFailure("FAIL", "integrity", "smoke-файл изменился")
    for path_text, digest in before.items():
        if sha256_bytes(Path(path_text).read_bytes()) != digest:
            raise GateFailure("FAIL", "integrity", f"файл изменился во время запуска: {path_text}")
    uv_proc = run_command("uv_version", [uv, "--version"], work, base, logs_dir, commands)
    uv_text = uv_proc.stdout.decode("utf-8", errors="replace").strip()
    notes = []
    if sys.version.split()[0] != "3.12.14":
        notes.append(f"CPython {sys.version.split()[0]}, на целевом Work была 3.12.14")
    if glibc != (2, 41):
        notes.append(f"glibc {glibc[0]}.{glibc[1]}, на целевом Work была 2.41")
    if uv_text != "uv 0.13.9 (x86_64-unknown-linux-gnu)":
        notes.append(f"uv {uv_text!r}, на целевом Work был uv 0.13.9")
    return {
        "status": "RUNTIME_READY",
        "mode": "source-run",
        "paths_usable": True,
        "runtime_sha256": RUNTIME_SHA256,
        "inner_sha256": INNER_SHA256,
        "commit": COMMIT,
        "declared_version": DECLARED_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "packaging_revision": "R2-autonomous",
        "cli_reported_version": "0.0.0",
        "cli_version_stdout": reported,
        "python": str(py.absolute()),
        "pythonpath": str(source_src),
        "checks_py": str(checks_py.resolve()),
        "work_dir": str(work.resolve()),
        "logs_dir": str(logs_dir.resolve()),
        "dependencies": verified["wheels"],
        "installed_distributions": installed,
        "include_system_site_packages": False,
        "commands": commands,
        "smoke": {
            "text_sha256": sha256_bytes(payload),
            "scan_exit": scan_proc.returncode,
            "validate_exit": validate_proc.returncode,
            "words": scan_obj["stats"]["words"],
            "context_mode": scan_obj["stats"]["contextMode"],
            "classifier_present": False,
            "ok": True,
            "warnings": [],
            "violations": [],
            "swapped_numbers": [],
            "coverage": coverage_obj.get("disposition"),
            "full_range_acceptance": coverage_obj.get("full_range_acceptance"),
            "helper_sha256": sha_obj.get("sha256"),
            "read_back_matches": True,
        },
        "host": {
            "python": sys.version,
            "executable": sys.executable,
            "implementation": sys.implementation.name,
            "system": platform.system(),
            "machine": platform.machine(),
            "platform": platform_line,
            "glibc": f"{glibc[0]}.{glibc[1]}",
            "uv": uv_text,
            "uv_path": uv,
        },
        "notes": notes,
        "CLI_INSTALL": "NOT_RUN",
        "LOCKED_PROJECT_RUN": "NOT_RUN",
        "scientific_acceptance": "PENDING",
    }


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")
    commands: list[dict[str, object]] = []
    state: dict[str, Path | None] = {"logs_dir": None}
    try:
        payload = prepare(argv, commands, state)
    except GateFailure as error:
        logs_dir = state["logs_dir"]
        return emit(failure_payload(error, commands, logs_dir), 1, logs_dir)
    except Exception as error:
        logs_dir = state["logs_dir"]
        wrapped = GateFailure("FAIL", "unexpected", f"{type(error).__name__}: {error}")
        return emit(failure_payload(wrapped, commands, logs_dir), 1, logs_dir)
    return emit(payload, 0, state["logs_dir"])


if __name__ == "__main__":
    sys.exit(main())
