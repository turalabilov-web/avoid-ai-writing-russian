"""Файловые сверки покрытия, хэшей и защищённых байтов.

Помощник не вызывает детектор, не ставит пакеты и не решает, сохранён ли
научный смысл. Он читает уже полученный JSON и сырые байты копий. Код выхода
0 означает только то, что JSON напечатан, а не то, что текст принят.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from bisect import bisect_right
from pathlib import Path
from typing import Any, TypedDict

ROLE = "file-check"
FILE_PASS = "FILE_CHECKS_PASS"
FILE_FAIL = "FILE_CHECKS_FAIL"
FILE_BLOCKED = "BLOCKED"
# Классы букв склеены в коде: в файле не должно быть латинской буквы внутри русского слова.
_CYR = "А-Яа-яЁё"
_LAT = "A-Za-z"
_LETTERS = _CYR + _LAT
_REVIEW_DECISIONS = frozenset({"ACCEPT", "REJECT", "UNRESOLVED"})
_CHANGE_FIELDS = ("before", "after", "locator", "defect", "permission", "source_claim", "candidate_claim")

_MARKER = re.compile(
    r"^[ \t]*<!--[ \t]*(aiw-ru|avoid-ai-writing):ignore-(start|end)[ \t]*-->[ \t]*$",
    re.MULTILINE,
)
_FENCE = re.compile(r"^(```|~~~)[^\n]*\n[\s\S]*?^\1[^\n]*$", re.MULTILINE)
_FRONT = re.compile(r"^---\n[\s\S]*?\n---(?:\n|$)")
_HEADING = re.compile(r"^#{1,6}[ \t]+.*$", re.MULTILINE)
_TABLE = re.compile(r"^[ \t]*\|.+\|[ \t]*$", re.MULTILINE)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _byte_offset(text: str, index: int) -> int:
    return len(text[:index].encode("utf-8"))


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def attest_bytes(data: bytes, *, representation: str = "text") -> dict[str, Any]:
    """Читаемость UTF-8, пустота и хэш. Байты не нормализуются."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return {
            "role": ROLE,
            "readable": False,
            "sha256": sha256_bytes(data),
            "byte_length": len(data),
            "empty": False,
            "whitespace_only": False,
            "representation": representation,
            "error": f"utf-8: {error.reason}",
            "text": None,
        }
    stripped = text.strip()
    return {
        "role": ROLE,
        "readable": True,
        "sha256": sha256_bytes(data),
        "byte_length": len(data),
        "empty": text == "",
        "whitespace_only": text != "" and stripped == "",
        "representation": representation,
        "error": None,
        "text": text,
    }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _error(path: str, problem: str) -> str:
    return f"{path}: {problem}"


def inspect_scan(stdout: str, exit_code: int, *, mock: bool = False) -> dict[str, Any]:
    """Схема ответа scan. Поля исходного объекта не исправляются."""
    errors: list[str] = []
    report: Any = None
    if exit_code != 0:
        errors.append(_error("exit_code", f"ожидался 0, получен {exit_code}"))
    try:
        report = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError as error:
        report = None
        errors.append(_error("json", str(error)))
    if report is None:
        errors.append(_error("json", "пустой stdout"))
    elif not isinstance(report, dict):
        errors.append(_error("json", f"нужен объект, получен {type(report).__name__}"))
        report = None
    words = None
    context = None
    ignored: int | None = None
    ignored_present = False
    classifier = False
    if isinstance(report, dict):
        if "score" not in report:
            errors.append(_error("score", "поле отсутствует"))
        elif not _is_int(report["score"]):
            errors.append(_error("score", "нужно целое число"))
        if "issues" not in report:
            errors.append(_error("issues", "поле отсутствует"))
        elif not isinstance(report["issues"], list):
            errors.append(_error("issues", "нужен список"))
        stats = report.get("stats", None)
        if not isinstance(stats, dict):
            errors.append(_error("stats", "поле отсутствует или это не объект"))
        else:
            if "words" not in stats:
                errors.append(_error("stats.words", "поле отсутствует"))
            elif not _is_int(stats["words"]) or stats["words"] < 0:
                errors.append(_error("stats.words", "нужно целое число не меньше нуля"))
            else:
                words = stats["words"]
            if "contextMode" not in stats:
                errors.append(_error("stats.contextMode", "поле отсутствует"))
            elif stats["contextMode"] != "academic":
                errors.append(_error("stats.contextMode", f"получено {stats['contextMode']!r}, для vak нужно academic"))
                context = stats["contextMode"] if isinstance(stats["contextMode"], str) else None
            else:
                context = "academic"
            if "ignoredRegions" in stats:
                ignored_present = True
                if not _is_int(stats["ignoredRegions"]) or stats["ignoredRegions"] < 0:
                    errors.append(_error("stats.ignoredRegions", "нужно целое число не меньше нуля"))
                else:
                    ignored = stats["ignoredRegions"]
        meta = report.get("meta", None)
        if not isinstance(meta, dict) or "schema" not in meta:
            errors.append(_error("meta.schema", "поле отсутствует"))
        if "classifier" in report:
            classifier = True
            errors.append(_error("classifier", "в диагностике этого навыка модели быть не должно"))
    return {
        "role": ROLE,
        "mock": mock,
        "exit_code": exit_code,
        "parsed": isinstance(report, dict),
        "schema_ok": not errors,
        "errors": errors,
        "words": words,
        "context_mode": context,
        "ignored_regions": ignored,
        "ignored_regions_present": ignored_present,
        "classifier_present": classifier,
    }


def inspect_validate(stdout: str, exit_code: int, *, mock: bool = False) -> dict[str, Any]:
    """Схема ответа validate. Отсутствующее поле не заменяется пустым списком."""
    errors: list[str] = []
    report: Any = None
    if exit_code not in (0, 1):
        errors.append(_error("exit_code", f"для разобранного validate ожидался 0 или 1, получен {exit_code}"))
    try:
        report = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError as error:
        report = None
        errors.append(_error("json", str(error)))
    if not isinstance(report, dict):
        errors.append(_error("json", "нужен объект"))
        report = None
    ok = None
    warnings: list[Any] = []
    warning_kinds: list[str] = []
    swapped_present = False
    if isinstance(report, dict):
        if "ok" not in report:
            errors.append(_error("ok", "поле отсутствует"))
        elif not isinstance(report["ok"], bool):
            errors.append(_error("ok", "нужно логическое значение, не строка и не число"))
        else:
            ok = report["ok"]
        for key in ("violations", "warnings", "swappedNumbers"):
            if key not in report:
                errors.append(_error(key, "поле отсутствует"))
            elif not isinstance(report[key], list):
                errors.append(_error(key, "нужен список"))
        if isinstance(report.get("warnings"), list):
            warnings = report["warnings"]
            warning_kinds = [item.get("kind", "") for item in warnings if isinstance(item, dict)]
        if isinstance(report.get("swappedNumbers"), list):
            swapped_present = True
            if report["swappedNumbers"] and "swappedNumbers" not in warning_kinds:
                warning_kinds.append("swappedNumbers")
        meta = report.get("meta", None)
        if not isinstance(meta, dict) or "schema" not in meta:
            errors.append(_error("meta.schema", "поле отсутствует"))
        if ok is True and exit_code not in (0,):
            errors.append(_error("exit_code", "ok true при коде, отличном от 0"))
        if ok is False and exit_code == 0:
            errors.append(_error("exit_code", "ok false при коде 0"))
    return {
        "role": ROLE,
        "mock": mock,
        "exit_code": exit_code,
        "parsed": isinstance(report, dict),
        "schema_ok": not errors and isinstance(report, dict),
        "errors": errors,
        "ok": ok,
        "warnings": warnings,
        "warning_kinds": warning_kinds,
        "swapped_numbers_present": swapped_present,
    }


def _inside(ranges: list[tuple[int, int]], index: int) -> bool:
    starts = [item[0] for item in ranges]
    k = bisect_right(starts, index) - 1
    return k >= 0 and ranges[k][0] <= index < ranges[k][1]


def marker_inventory(text: str) -> dict[str, Any]:
    """Те же границы пометок, что у детектора: строка целиком, вне блока кода.

    Вложенность закрывается внешней пометкой конца. Незакрытая тянется до конца
    текста. Лишняя пометка конца область не открывает. Это учёт, не новая маска.
    """
    fences = [match.span() for match in _FENCE.finditer(text)]
    ranges: list[tuple[int, int]] = []
    closed_flags: list[bool] = []
    families: list[str] = []
    depth = 0
    start = 0
    start_family = ""
    nested = False
    stray: list[int] = []
    lines: list[dict[str, Any]] = []
    for match in _MARKER.finditer(text):
        fenced = _inside(fences, match.start())
        kind = match.group(2)
        family = match.group(1)
        lines.append(
            {
                "line": _line_of(text, match.start()),
                "kind": kind,
                "family": family,
                "inside_fence": fenced,
            }
        )
        if fenced:
            continue
        if kind == "start":
            if depth > 0:
                nested = True
            if depth == 0:
                start = match.start()
                start_family = family
            depth += 1
        elif depth:
            depth -= 1
            if depth == 0:
                ranges.append((start, match.end()))
                closed_flags.append(True)
                families.append(start_family)
        else:
            stray.append(_line_of(text, match.start()))
    if depth:
        ranges.append((start, len(text)))
        closed_flags.append(False)
        families.append(start_family)
    regions = []
    for (region_start, region_end), is_closed, family in zip(ranges, closed_flags, families, strict=True):
        regions.append(
            {
                "start": region_start,
                "end": region_end,
                "byte_start": _byte_offset(text, region_start),
                "byte_end": _byte_offset(text, region_end),
                "start_line": _line_of(text, region_start),
                "end_line": _line_of(text, max(region_start, region_end - 1)),
                "closed": is_closed,
                "family": family,
            }
        )
    structural: list[dict[str, str]] = []
    if _FRONT.search(text):
        structural.append({"kind": "frontmatter", "reason": "шапка YAML в счётчик слов не входит"})
    for match in _FENCE.finditer(text):
        structural.append(
            {
                "kind": "fence",
                "reason": "блок кода детектор не читает как прозу",
                "locator": f"lines {_line_of(text, match.start())}-{_line_of(text, max(match.start(), match.end() - 1))}",
            }
        )
    if _TABLE.search(text):
        structural.append({"kind": "table", "reason": "строки таблицы не дают процента покрытия по словам"})
    return {
        "role": ROLE,
        "regions": regions,
        "nested": nested,
        "unclosed": any(not item["closed"] for item in regions),
        "stray_end_lines": stray,
        "marker_lines": lines,
        "structural_notes": structural,
    }


def _region_key(region: dict[str, Any]) -> tuple[int, int]:
    return (region["start"], region["end"])


def coverage_decision(
    source: str,
    scan: dict[str, Any],
    *,
    attest: dict[str, Any] | None = None,
    scope: str = "full",
    justified_spans: list[tuple[int, int]] | None = None,
    missing_required: list[str] | None = None,
    representation: str = "text",
) -> dict[str, Any]:
    """Решение о полноте запрошенного диапазона. Процент по словам не вычисляется."""
    reasons: list[str] = []
    if attest is None:
        attest = attest_bytes(source.encode("utf-8"), representation=representation)
    inventory = (
        marker_inventory(source)
        if attest.get("readable")
        else {
            "regions": [],
            "structural_notes": [],
            "unclosed": False,
            "nested": False,
            "stray_end_lines": [],
        }
    )
    justified = set(justified_spans or [])
    exclusions = []
    for region in inventory["regions"]:
        key = _region_key(region)
        agreed = key in justified
        exclusions.append(
            {
                "locator": (
                    f"bytes {region['byte_start']}:{region['byte_end']} "
                    f"lines {region['start_line']}-{region['end_line']}"
                ),
                "start": region["start"],
                "end": region["end"],
                "reason": (
                    "пометка ignore в исходнике; это не разрешение автора удалить или скрыть текст"
                    + ("; пометка не закрыта и тянется до конца" if not region["closed"] else "")
                ),
                "family": region["family"],
                "decision": "оставить байты без изменений и не удалять пометку",
                "justified": agreed,
            }
        )
    unjustified = [item for item in exclusions if not item["justified"]]
    words = scan.get("words")
    scanned = []
    if isinstance(words, int):
        scanned.append(
            {
                "block_id": "requested-range",
                "locator": "весь запрошенный диапазон" if scope == "full" else "согласованный ограниченный диапазон",
                "words": words,
                "exit_code": scan.get("exit_code"),
                "context_mode": scan.get("context_mode"),
            }
        )
    global_blocked = False
    false_clean = False
    if not attest.get("readable"):
        global_blocked = True
        reasons.append("источник не читается как UTF-8")
    if attest.get("empty") or attest.get("whitespace_only"):
        global_blocked = True
        false_clean = True
        reasons.append("пустой или пробельный диапазон: нулевой балл не означает полноту")
    if representation not in ("text", "extracted-confirmed"):
        global_blocked = True
        reasons.append("извлечение DOCX или PDF не подтверждено, хэш копии не равен хэшу контейнера")
    if missing_required:
        global_blocked = True
        reasons.append("нет текста обязательного блока: " + ", ".join(missing_required))
    if not scan.get("schema_ok"):
        global_blocked = True
        reasons.extend(scan.get("errors") or ["ответ scan не разобран"])
    found = len(inventory["regions"])
    cli_ignored = scan.get("ignored_regions")
    if scan.get("parsed") and scan.get("schema_ok"):
        if cli_ignored is None and found != 0:
            global_blocked = True
            reasons.append("в тексте есть пометки ignore, а stats.ignoredRegions отсутствует")
        elif cli_ignored is not None and cli_ignored != found:
            global_blocked = True
            reasons.append(f"число областей ignore не сходится: помощник {found}, CLI {cli_ignored}")
    if unjustified and scope == "full":
        global_blocked = True
        false_clean = True
        reasons.append("часть запрошенного диапазона исключена пометкой и не согласована отдельно")
    if unjustified and scope == "limited":
        global_blocked = True
        reasons.append("ограниченный диапазон не покрывает все фактические исключения")
    if (
        isinstance(words, int)
        and words == 0
        and found
        and not attest.get("empty")
        and not attest.get("whitespace_only")
    ):
        global_blocked = True
        false_clean = True
        reasons.append("машинное покрытие нулевое: проза целиком скрыта пометками")
    letters = bool(re.search(r"[" + _LETTERS + r"]", source))
    structural_only = bool(inventory["structural_notes"]) and not letters_outside_structural(source)
    if isinstance(words, int) and words == 0 and not found and letters and not structural_only and not global_blocked:
        global_blocked = True
        false_clean = True
        reasons.append("слов ноль, а объяснимого исключения нет")
    limited_ok = (
        not global_blocked
        and scope == "limited"
        and not unjustified
        and isinstance(words, int)
        and words > 0
        and bool(exclusions)
    )
    full_ok = (
        not global_blocked
        and not exclusions
        and isinstance(words, int)
        and words > 0
        and attest.get("readable")
        and not attest.get("whitespace_only")
    )
    if structural_only and isinstance(words, int) and words == 0 and not global_blocked:
        disposition = "LIMITED"
        reasons.append("обычная разметка без прозы: глобальная блокировка не ставится, полнота прозы не заявляется")
    elif global_blocked:
        disposition = "BLOCKED"
    elif limited_ok:
        disposition = "LIMITED"
        reasons.append("вывод относится только к согласованному диапазону, исключённый текст не проверен")
    elif full_ok:
        disposition = "COVERED"
        reasons.append("проза диапазона просканирована; процент покрытия по словам не заявляется")
    else:
        disposition = "BLOCKED"
        global_blocked = True
        reasons.append("полнота запрошенного диапазона не доказана")
    return {
        "role": ROLE,
        "disposition": disposition,
        "global_blocked": global_blocked or disposition == "BLOCKED",
        "full_range_acceptance": bool(full_ok),
        "limited_scope_acceptance": bool(limited_ok),
        "false_clean": false_clean,
        "absolute_word_coverage": False,
        "reasons": reasons,
        "exclusions": exclusions,
        "structural_notes": inventory["structural_notes"],
        "scanned_blocks": scanned,
        "words": words,
        "ignored_regions": cli_ignored,
        "requested_scope": scope,
        "nested": inventory.get("nested", False),
        "unclosed": inventory.get("unclosed", False),
        "stray_end_lines": inventory.get("stray_end_lines", []),
        "missing_required": list(missing_required or []),
    }


def letters_outside_structural(text: str) -> bool:
    """Есть ли буквы вне шапки, ограждённого кода и строк таблицы."""
    chars = list(text)
    spans = []
    front = _FRONT.search(text)
    if front:
        spans.append(front.span())
    spans.extend(match.span() for match in _FENCE.finditer(text))
    spans.extend(match.span() for match in _TABLE.finditer(text))
    for start, end in spans:
        for index in range(start, end):
            chars[index] = " "
    return bool(re.search(r"[" + _LETTERS + r"]", "".join(chars)))


def _sections(text: str) -> list[tuple[str, int, int]]:
    marks = list(_HEADING.finditer(text))
    if not marks:
        return [("", 0, len(text))]
    spans: list[tuple[str, int, int]] = []
    if marks[0].start() > 0:
        spans.append(("", 0, marks[0].start()))
    for index, mark in enumerate(marks):
        end = marks[index + 1].start() if index + 1 < len(marks) else len(text)
        spans.append((mark.group(0).rstrip("\r"), mark.start(), end))
    return spans


def _section_at(spans: list[tuple[str, int, int]], index: int) -> str:
    for heading, start, end in spans:
        if start <= index < end:
            return heading
    return ""


def _find_all(text: str, exact: str) -> list[int]:
    if exact == "":
        return []
    found: list[int] = []
    start = 0
    while True:
        index = text.find(exact, start)
        if index < 0:
            return found
        found.append(index)
        start = index + len(exact)


def _byte_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    return len(text[:start].encode("utf-8")), len(text[:end].encode("utf-8"))


def _slice_bytes(data: bytes, text: str, start: int, end: int) -> bytes:
    byte_start, byte_end = _byte_bounds(text, start, end)
    return data[byte_start:byte_end]


def _line_ending_hint(source: str, exact: str) -> str:
    """Подсказка, почему спецификация не легла на сырой текст. Ничего не переписывает."""
    if "\r" not in exact and "\n" in exact and exact.replace("\n", "\r\n") in source:
        return "LF-спецификация не привязывается к сырому фрагменту с CRLF"
    if "\r\n" in exact and exact not in source and exact.replace("\r\n", "\n") in source:
        return "CRLF-спецификация не привязывается к фрагменту с LF"
    return ""


class _Located(TypedDict):
    start: int
    section: str
    occurrence: int


def _as_bytes(text: str, data: bytes | None) -> bytes:
    if data is None:
        return text.encode("utf-8")
    return data


def bind_protected(
    source: str,
    specs: list[dict[str, Any]],
    *,
    source_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Реестр до правки. Хэш считается по срезу сырых байтов, не по нормализованной копии."""
    raw = _as_bytes(source, source_bytes)
    source_sha = sha256_bytes(raw)
    errors: list[str] = []
    try:
        if raw.decode("utf-8") != source:
            errors.append("текст источника не совпал с переданными байтами")
    except UnicodeDecodeError as error:
        errors.append(f"utf-8: {error.reason}")
    if errors:
        return {
            "role": ROLE,
            "ok": False,
            "frozen": False,
            "unverifiable": True,
            "errors": errors,
            "items": [],
            "source_sha256": source_sha,
        }
    spans = _sections(source)
    items: list[dict[str, Any]] = []
    for spec in specs:
        identifier = str(spec.get("id", ""))
        exact = spec.get("exact")
        if not isinstance(exact, str) or exact == "":
            errors.append(f"{identifier}: пустой фрагмент не регистрируется")
            continue
        hits = _find_all(source, exact)
        described: list[_Located] = []
        for index in hits:
            section = _section_at(spans, index)
            section_hits = [hit for hit in hits if _section_at(spans, hit) == section]
            described.append({"start": index, "section": section, "occurrence": section_hits.index(index)})
        wanted_section = spec.get("section")
        wanted_occurrence = spec.get("occurrence")
        chosen = described
        if isinstance(wanted_section, str):
            chosen = [item for item in chosen if item["section"] == wanted_section]
        if wanted_occurrence is not None:
            chosen = [item for item in chosen if item["occurrence"] == wanted_occurrence]
        if len(chosen) != 1:
            hint = _line_ending_hint(source, exact) if not chosen else ""
            why = "нет однозначной привязки" if chosen else "фрагмент не найден"
            suffix = f"; {hint}" if hint else ""
            errors.append(f"{identifier}: в источнике {why}{suffix} ({len(chosen)} кандидатов)")
            continue
        pick = chosen[0]
        char_end = pick["start"] + len(exact)
        piece = _slice_bytes(raw, source, pick["start"], char_end)
        if piece.decode("utf-8") != exact:
            errors.append(f"{identifier}: срез байтов не совпал со спецификацией")
            continue
        section_span = next(
            (
                (start, end)
                for heading, start, end in spans
                if heading == pick["section"] and start <= pick["start"] < end
            ),
            None,
        )
        covers_section = section_span == (pick["start"], char_end)
        byte_start, byte_end = _byte_bounds(source, pick["start"], char_end)
        items.append(
            {
                "id": identifier,
                "locator": f"section={pick['section']};occurrence={pick['occurrence']};bytes={byte_start}:{byte_end}",
                "exact": exact,
                "sha256": sha256_bytes(piece),
                "byte_length": len(piece),
                "start": pick["start"],
                "end": char_end,
                "byte_start": byte_start,
                "byte_end": byte_end,
                "section": pick["section"],
                "occurrence": pick["occurrence"],
                "count_in_source": source.count(exact),
                "covers_section": covers_section,
            }
        )
    items.sort(key=lambda item: (item["start"], item["id"]))
    for order, item in enumerate(items):
        item["order"] = order
    return {
        "role": ROLE,
        "ok": not errors,
        "frozen": False,
        "unverifiable": bool(errors),
        "errors": errors,
        "items": items,
        "source_sha256": source_sha,
    }


def _frozen_registry_errors(source: str, source_bytes: bytes, registry: dict[str, Any]) -> list[str]:
    if registry.get("source_sha256") != sha256_bytes(source_bytes):
        return ["реестр привязан к другому SHA-256 источника"]
    items = registry.get("items")
    if not isinstance(items, list):
        return ["в замороженном реестре нет списка вхождений"]
    errors: list[str] = []
    required = (
        "id",
        "exact",
        "sha256",
        "byte_length",
        "byte_start",
        "byte_end",
        "start",
        "section",
        "occurrence",
        "count_in_source",
        "covers_section",
    )
    for item in items:
        if not isinstance(item, dict) or any(key not in item for key in required):
            errors.append("запись реестра неполная")
            continue
        start = item["byte_start"]
        end = item["byte_end"]
        if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start <= end <= len(source_bytes):
            errors.append(f"{item['id']}: диапазон байтов реестра вне источника")
            continue
        piece = source_bytes[start:end]
        if len(piece) != item["byte_length"] or sha256_bytes(piece) != item["sha256"]:
            errors.append(f"{item['id']}: срез реестра не совпал с байтами источника")
            continue
        try:
            if piece.decode("utf-8") != item["exact"]:
                errors.append(f"{item['id']}: срез реестра не совпал со строкой фрагмента")
        except UnicodeDecodeError:
            errors.append(f"{item['id']}: срез реестра не декодируется")
    if not errors and source_bytes.decode("utf-8") != source:
        errors.append("текст источника не совпал с переданными байтами")
    return errors


def _protected_result(
    status: str,
    reasons: list[str],
    items: list[dict[str, Any]],
    *,
    failure_class: str | None,
    registry_empty: bool,
    source_sha: str,
    candidate_sha: str,
) -> dict[str, Any]:
    return {
        "role": ROLE,
        "status": status,
        "failure_class": failure_class,
        "reasons": [item for item in reasons if item],
        "items": items,
        "registry_empty": registry_empty,
        "source_sha256": source_sha,
        "candidate_sha256": candidate_sha,
        "rebound": False,
    }


def compare_protected(
    source: str,
    candidate: str,
    specs: list[dict[str, Any]] | dict[str, Any],
    *,
    lifted: dict[str, str] | None = None,
    source_bytes: bytes | None = None,
    candidate_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Побайтовая сверка по разделу и номеру вхождения. Реестр по кандидату не пересобирается."""
    raw_source = _as_bytes(source, source_bytes)
    raw_candidate = _as_bytes(candidate, candidate_bytes)
    source_sha = sha256_bytes(raw_source)
    candidate_sha = sha256_bytes(raw_candidate)

    def blocked(reasons: list[str], *, failure_class: str = "registry", registry_empty: bool = False) -> dict[str, Any]:
        return _protected_result(
            "BLOCKED",
            reasons,
            [],
            failure_class=failure_class,
            registry_empty=registry_empty,
            source_sha=source_sha,
            candidate_sha=candidate_sha,
        )

    try:
        if raw_source.decode("utf-8") != source or raw_candidate.decode("utf-8") != candidate:
            return blocked(["текст не совпал с переданными байтами"])
    except UnicodeDecodeError as error:
        return blocked([f"utf-8: {error.reason}"])
    if isinstance(specs, dict):
        if specs.get("frozen") is not True:
            return blocked(["реестр без признака frozen нельзя применить молча"])
        if specs.get("ok") is False or specs.get("unverifiable") is True:
            return blocked(
                list(specs.get("errors") or ["реестр помечен как непроверяемый"]), registry_empty=not specs.get("items")
            )
        registry_errors = _frozen_registry_errors(source, raw_source, specs)
        if registry_errors:
            return blocked(registry_errors, registry_empty=not specs.get("items"))
        items = list(specs.get("items") or [])
        registry_empty = not items and not specs.get("items")
    elif isinstance(specs, list):
        registry = bind_protected(source, specs, source_bytes=raw_source)
        if registry["unverifiable"]:
            return blocked(registry["errors"], registry_empty=not specs)
        items = registry["items"]
        registry_empty = not specs
    else:
        return blocked(["спецификация защиты имеет неизвестную форму"])
    lifted = lifted or {}
    results: list[dict[str, Any]] = []
    located: list[tuple[int, int, str]] = []
    candidate_spans = _sections(candidate)
    heading_counts: dict[str, int] = {}
    for heading, _, _ in candidate_spans:
        heading_counts[heading] = heading_counts.get(heading, 0) + 1
    for item in items:
        reason = lifted.get(item["id"], "")
        if item["id"] in lifted:
            if not str(reason).strip():
                results.append({"id": item["id"], "status": "BLOCKED", "reason": "снятие защиты без записи решения"})
            else:
                results.append({"id": item["id"], "status": "LIFTED", "reason": reason})
            continue
        if item["section"] and heading_counts.get(item["section"], 0) != 1:
            results.append({"id": item["id"], "status": "BLOCKED", "reason": "раздел в копии не однозначен"})
            continue
        section_span = next(
            ((start, end) for heading, start, end in candidate_spans if heading == item["section"]),
            None,
        )
        if section_span is None:
            results.append(
                {
                    "id": item["id"],
                    "status": "FAIL",
                    "reason": "раздел пропал",
                    "elsewhere": item["exact"] in candidate,
                    "failure_class": "protected_bytes",
                }
            )
            continue
        section_text = candidate[section_span[0] : section_span[1]]
        source_count = item["count_in_source"]
        candidate_count = candidate.count(item["exact"])
        if item.get("covers_section") and section_text != item["exact"]:
            results.append(
                {
                    "id": item["id"],
                    "status": "FAIL",
                    "reason": "байты защищённого раздела изменились",
                    "elsewhere": item["exact"] in candidate,
                    "failure_class": "protected_bytes",
                }
            )
            continue
        local_hits = _find_all(section_text, item["exact"])
        if item["occurrence"] >= len(local_hits):
            results.append(
                {
                    "id": item["id"],
                    "status": "FAIL",
                    "reason": "фрагмент не найден в своём разделе",
                    "elsewhere": item["exact"] in candidate,
                    "source_count": source_count,
                    "candidate_count": candidate_count,
                    "failure_class": "protected_bytes",
                }
            )
            continue
        if candidate_count != source_count:
            results.append(
                {
                    "id": item["id"],
                    "status": "FAIL",
                    "reason": "число вхождений изменилось",
                    "source_count": source_count,
                    "candidate_count": candidate_count,
                    "failure_class": "protected_bytes",
                }
            )
            continue
        absolute = section_span[0] + local_hits[item["occurrence"]]
        piece = _slice_bytes(raw_candidate, candidate, absolute, absolute + len(item["exact"]))
        if piece.decode("utf-8") != item["exact"] or sha256_bytes(piece) != item["sha256"]:
            results.append(
                {
                    "id": item["id"],
                    "status": "FAIL",
                    "reason": "байты фрагмента отличаются",
                    "failure_class": "protected_bytes",
                }
            )
            continue
        located.append((item["start"], absolute, item["id"]))
        results.append(
            {
                "id": item["id"],
                "status": "PASS",
                "source_start": item["start"],
                "candidate_start": absolute,
                "sha256": item["sha256"],
                "byte_length": item["byte_length"],
                "section": item["section"],
                "occurrence": item["occurrence"],
                "shifted": absolute != item["start"],
                "locator": item.get("locator", ""),
            }
        )
    order_broken: list[str] = []
    for left in range(len(located)):
        for right in range(left + 1, len(located)):
            source_before = located[left][0] < located[right][0]
            candidate_before = located[left][1] < located[right][1]
            if source_before != candidate_before:
                order_broken.append(f"{located[left][2]}->{located[right][2]}")
    if order_broken:
        for result in results:
            if result["status"] == "PASS":
                result["status"] = "FAIL"
                result["failure_class"] = "protected_bytes"
                result["reason"] = "порядок защищённых фрагментов изменился: " + ", ".join(order_broken)
    statuses = {item["status"] for item in results}
    if "BLOCKED" in statuses:
        status = "BLOCKED"
        failure_class: str | None = "correspondence"
    elif "FAIL" in statuses:
        status = "FAIL"
        failure_class = "protected_bytes"
    else:
        status = "PASS"
        failure_class = None
    reasons: list[str] = []
    for item in results:
        reason = item.get("reason", "")
        if item["status"] != "PASS" and reason and reason not in reasons:
            reasons.append(reason)
    return _protected_result(
        status,
        reasons,
        results,
        failure_class=failure_class,
        registry_empty=registry_empty,
        source_sha=source_sha,
        candidate_sha=candidate_sha,
    )


def bind_review(
    review: dict[str, Any] | None,
    source_sha256: str,
    candidate_sha256: str,
) -> dict[str, Any]:
    """Проверяет привязку записи сверки к байтам. Содержание вывода не оценивает."""
    if not isinstance(review, dict):
        return {
            "role": ROLE,
            "bound": False,
            "stale": False,
            "incomplete": True,
            "decision_recorded": None,
            "legacy_declaration": False,
            "blocks_editor_delivery": False,
            "scientific_acceptance": False,
            "errors": ["запись сверки не объект"],
        }
    legacy = "style_only" in review or ("invariants_checked" in review and "source_sha256" not in review)
    decision = review.get("decision")
    recorded = decision if isinstance(decision, str) else None
    errors: list[str] = []
    src = review.get("source_sha256")
    cand = review.get("candidate_sha256")
    if not isinstance(src, str) or not isinstance(cand, str):
        errors.append("в записи нет SHA-256 исходника и чистовика")
        return {
            "role": ROLE,
            "bound": False,
            "stale": False,
            "incomplete": True,
            "decision_recorded": recorded,
            "legacy_declaration": legacy,
            "blocks_editor_delivery": recorded in {"REJECT", "UNRESOLVED"},
            "scientific_acceptance": False,
            "errors": errors,
        }
    stale = src != source_sha256 or cand != candidate_sha256
    if stale:
        errors.append("SHA-256 записи не совпал с фактическими байтами")
    if decision not in _REVIEW_DECISIONS:
        errors.append("решение сверки не одно из ACCEPT, REJECT, UNRESOLVED")
    text_changed = source_sha256 != candidate_sha256
    changes = review.get("changes")
    if text_changed:
        if not isinstance(changes, list) or not changes:
            errors.append("для изменённой пары нужен список изменений")
        elif isinstance(changes, list):
            for index, change in enumerate(changes):
                if not isinstance(change, dict):
                    errors.append(f"changes[{index}] не объект")
                    continue
                for key in _CHANGE_FIELDS:
                    if not str(change.get(key, "")).strip():
                        errors.append(f"changes[{index}].{key} пусто")
    elif changes not in (None, []) and not isinstance(changes, list):
        errors.append("changes не список")
    bound = not errors
    return {
        "role": ROLE,
        "bound": bound,
        "stale": stale,
        "incomplete": not bound and not stale,
        "decision_recorded": recorded,
        "legacy_declaration": legacy,
        "blocks_editor_delivery": recorded in {"REJECT", "UNRESOLVED"} and not stale,
        "scientific_acceptance": False,
        "errors": errors,
    }


def aggregate_file_checks(
    source: str,
    candidate: str,
    coverage: dict[str, Any],
    *,
    source_bytes: bytes | None = None,
    candidate_bytes: bytes | None = None,
    protected: dict[str, Any] | None = None,
    validation: dict[str, Any] | None = None,
    review: dict[str, Any] | None = None,
    scan: dict[str, Any] | None = None,
    protected_required: bool = False,
    mock: bool = False,
    ignored_inputs: list[str] | None = None,
) -> dict[str, Any]:
    """Сводит объективные файловые результаты. Научный статус текста не назначает."""
    raw_source = _as_bytes(source, source_bytes)
    raw_candidate = _as_bytes(candidate, candidate_bytes)
    source_sha = sha256_bytes(raw_source)
    candidate_sha = sha256_bytes(raw_candidate)
    text_changed = raw_source != raw_candidate
    reasons: list[str] = []
    file_status = FILE_BLOCKED
    result_scope = None
    full_range = False
    mocked = bool(
        mock or (validation and validation.get("mock")) or (scan and scan.get("mock")) or coverage.get("mock")
    )
    review_binding = bind_review(review, source_sha, candidate_sha) if review is not None else None
    covered = bool(coverage.get("full_range_acceptance") or coverage.get("limited_scope_acceptance"))
    structural_only = coverage.get("disposition") == "LIMITED" and not coverage.get("global_blocked") and not covered
    if mocked:
        reasons.append("прогон помечен как mock и не является работой линтера")
    elif protected_required and (protected is None or protected.get("registry_empty")):
        reasons.append("реестр защищённых фрагментов обязателен и пуст")
    elif protected and protected.get("status") == "BLOCKED":
        reasons.extend(protected.get("reasons") or ["защищённый фрагмент нельзя проверить"])
    elif protected and protected.get("status") == "FAIL":
        file_status = FILE_FAIL
        reasons.extend(protected.get("reasons") or ["защищённые байты не сохранены"])
    elif coverage.get("global_blocked") or (not covered and not structural_only):
        reasons.extend(coverage.get("reasons") or ["покрытие не позволяет принять файлы"])
    elif validation is None or not validation.get("parsed"):
        reasons.append("validate не выполнен или ответ не разобран")
    elif not validation.get("schema_ok"):
        reasons.extend(validation.get("errors") or ["схема validate не сошлась"])
    elif validation.get("exit_code") not in (0, 1) or validation.get("ok") is None:
        reasons.append("validate завершился сбоем")
    elif validation.get("ok") is False:
        file_status = FILE_FAIL
        reasons.append("validate вернул ok false")
    elif validation.get("warning_kinds"):
        file_status = FILE_FAIL
        reasons.append(
            "есть предупреждения validate, помощник их не закрывает: " + ", ".join(validation["warning_kinds"])
        )
    elif coverage.get("full_range_acceptance"):
        file_status = FILE_PASS
        result_scope = "full"
        full_range = True
        reasons.append("файловые проверки диапазона сошлись; это не научная приёмка")
    elif coverage.get("limited_scope_acceptance"):
        file_status = FILE_PASS
        result_scope = "limited"
        reasons.append("файловая проверка относится только к согласованному диапазону")
    elif structural_only:
        file_status = FILE_PASS
        result_scope = "structural"
        reasons.append("обычная разметка без прозы не блокирует файл; полнота прозы не заявлена")
    else:
        reasons.append("полнота запрошенного диапазона не доказана")
    if review_binding and review_binding.get("stale"):
        reasons.append("запись сверки не совпала с фактическими SHA-256")
        if file_status == FILE_PASS:
            file_status = FILE_BLOCKED
            full_range = False
            result_scope = None
    return {
        "role": ROLE,
        "file_status": file_status,
        "full_range_file_pass": bool(full_range and file_status == FILE_PASS),
        "result_scope": result_scope if file_status == FILE_PASS else None,
        "text_changed": text_changed,
        "semantic_review_required": text_changed,
        "scientific_acceptance": False,
        "reasons": [item for item in reasons if item],
        "source_sha256": source_sha,
        "candidate_sha256": candidate_sha,
        "review_binding": review_binding,
        "mock": mocked,
        "protected_status": None if protected is None else protected.get("status"),
        "warning_kinds": [] if not validation else list(validation.get("warning_kinds") or []),
        "ignored_inputs": list(ignored_inputs or []),
    }


def read_back(path: str, expected_sha256: str) -> dict[str, Any]:
    """Сверяет байты, прочитанные с диска после записи, с ожидаемым хэшем."""
    _data, attest = _read_attest(path)
    actual = attest.get("sha256")
    return {
        "role": ROLE,
        "expected_sha256": expected_sha256,
        "actual_sha256": actual,
        "matches": actual == expected_sha256 and bool(actual),
        "readable": bool(attest.get("readable")),
        "byte_length": attest.get("byte_length"),
        "error": attest.get("error"),
        "scientific_acceptance": False,
    }


def _read_attest(path: str) -> tuple[bytes, dict[str, Any]]:
    try:
        data = Path(path).read_bytes()
    except OSError as error:
        return b"", {
            "role": ROLE,
            "readable": False,
            "sha256": None,
            "byte_length": 0,
            "empty": False,
            "whitespace_only": False,
            "representation": "text",
            "error": str(error),
            "text": None,
        }
    return data, attest_bytes(data)


def _load_json(path: str) -> tuple[Any, str | None]:
    try:
        data = Path(path).read_bytes()
    except OSError as error:
        return None, str(error)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return None, f"utf-8: {error.reason}"
    try:
        return json.loads(text), None
    except json.JSONDecodeError as error:
        return None, str(error)


def _emit(payload: dict[str, Any]) -> int:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return 0


def _blocked(reasons: list[str], **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "role": ROLE,
        "status": "BLOCKED",
        "file_status": FILE_BLOCKED,
        "scientific_acceptance": False,
        "semantic_review_required": False,
        "reasons": reasons,
    }
    payload.update(extra)
    return payload


def _texts_from_request(
    request: dict[str, Any], key: str
) -> tuple[bytes | None, dict[str, Any] | None, str | None, str | None]:
    path_key = f"{key}_path"
    has_path = bool(request.get(path_key))
    has_text = key in request
    if has_path and has_text:
        return None, None, None, f"одновременно заданы {key} и {path_key}"
    if has_path:
        data, attest = _read_attest(str(request[path_key]))
        if not attest.get("readable"):
            return data, attest, None, attest.get("error") or "файл не прочитан"
        return data, attest, attest["text"], None
    if has_text:
        text = request[key]
        if not isinstance(text, str):
            return None, None, None, f"{key} не строка"
        data = text.encode("utf-8")
        return data, attest_bytes(data), text, None
    return None, None, None, f"нет {key}"


def _stdout_from_request(request: dict[str, Any], key: str) -> str:
    path_key = f"{key}_path"
    if request.get(path_key):
        _data, attest = _read_attest(str(request[path_key]))
        if not attest.get("readable"):
            return ""
        return attest["text"] or ""
    value = request.get(key, "")
    return value if isinstance(value, str) else ""


def _coverage_from_args(source: str, attest: dict[str, Any], scan: dict[str, Any], args: Any) -> dict[str, Any]:
    spans = []
    for item in args.justified:
        start, end = item.split(":", 1)
        spans.append((int(start), int(end)))
    return coverage_decision(
        source,
        scan,
        attest=attest,
        scope=args.scope,
        justified_spans=spans,
        missing_required=args.missing_block,
        representation=args.representation,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Файловые сверки навыка медицинской редактуры")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sha = sub.add_parser("sha256")
    sha.add_argument("file")

    cov = sub.add_parser("coverage")
    cov.add_argument("--source", required=True)
    cov.add_argument("--scan-stdout", required=True)
    cov.add_argument("--exit-code", type=int, required=True)
    cov.add_argument("--scope", choices=("full", "limited"), default="full")
    cov.add_argument("--representation", default="text")
    cov.add_argument("--justified", action="append", default=[])
    cov.add_argument("--missing-block", action="append", default=[])
    cov.add_argument("--mock", action="store_true")

    bind = sub.add_parser("bind")
    bind.add_argument("--source", required=True)
    bind.add_argument("--spec", required=True)

    protect = sub.add_parser("protect")
    protect.add_argument("--source", required=True)
    protect.add_argument("--candidate", required=True)
    protect.add_argument("--spec")
    protect.add_argument("--registry")
    protect.add_argument("--lifted")

    back = sub.add_parser("read-back")
    back.add_argument("--file", required=True)
    back.add_argument("--sha256", required=True)

    gate = sub.add_parser("gate")
    gate.add_argument("--request", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "sha256":
        data, attest = _read_attest(args.file)
        if attest.get("sha256") is None:
            return _emit(_blocked([attest.get("error") or "файл не прочитан"]))
        return _emit({"role": ROLE, "sha256": attest["sha256"], "byte_length": len(data)})
    if args.cmd == "coverage":
        _data, attest = _read_attest(args.source)
        _scan_data, scan_attest = _read_attest(args.scan_stdout)
        if not scan_attest.get("readable"):
            return _emit(_blocked([scan_attest.get("error") or "stdout scan не прочитан"]))
        scan = inspect_scan(scan_attest["text"] or "", args.exit_code, mock=args.mock)
        source = attest["text"] if attest.get("readable") else ""
        return _emit(_coverage_from_args(source, attest, scan, args))
    if args.cmd == "bind":
        specs, error = _load_json(args.spec)
        if error:
            return _emit(_blocked([error]))
        if not isinstance(specs, list):
            return _emit(_blocked(["спецификация bind должна быть списком"]))
        data, attest = _read_attest(args.source)
        if not attest.get("readable"):
            return _emit(_blocked([attest.get("error") or "источник не прочитан"]))
        registry = bind_protected(attest["text"], specs, source_bytes=data)
        registry["frozen"] = bool(registry["ok"])
        return _emit(registry)
    if args.cmd == "protect":
        if bool(args.spec) == bool(args.registry):
            return _emit(_blocked(["нужен ровно один из --spec и --registry"]))
        source_data, source_attest = _read_attest(args.source)
        candidate_data, candidate_attest = _read_attest(args.candidate)
        if not source_attest.get("readable") or not candidate_attest.get("readable"):
            return _emit(
                _blocked(
                    [
                        item
                        for item in (
                            None if source_attest.get("readable") else source_attest.get("error"),
                            None if candidate_attest.get("readable") else candidate_attest.get("error"),
                        )
                        if item
                    ]
                )
            )
        lifted = None
        if args.lifted:
            loaded, error = _load_json(args.lifted)
            if error:
                return _emit(_blocked([error]))
            if not isinstance(loaded, dict):
                return _emit(_blocked(["снятие защиты должно быть объектом"]))
            lifted = {str(key): str(value) for key, value in loaded.items()}
        if args.registry:
            loaded, error = _load_json(args.registry)
        else:
            loaded, error = _load_json(args.spec)
        if error:
            return _emit(_blocked([error or "спецификация не прочитана"]))
        return _emit(
            compare_protected(
                source_attest["text"],
                candidate_attest["text"],
                loaded,
                lifted=lifted,
                source_bytes=source_data,
                candidate_bytes=candidate_data,
            )
        )
    if args.cmd == "read-back":
        return _emit(read_back(args.file, args.sha256))
    request, error = _load_json(args.request)
    if error or not isinstance(request, dict):
        return _emit(_blocked([error or "запрос gate должен быть объектом"]))
    ignored = [key for key in ("edit_allowed", "warnings_resolved", "semantic_review") if key in request]
    source_data, _source_attest, source, source_error = _texts_from_request(request, "source")
    candidate_data, _candidate_attest, candidate, candidate_error = _texts_from_request(request, "candidate")
    if source is None or candidate is None or source_data is None or candidate_data is None:
        return _emit(_blocked([item for item in (source_error, candidate_error) if item], ignored_inputs=ignored))
    review = request.get("review")
    if review is None and "semantic_review" in request:
        review = request.get("semantic_review")
    scan = inspect_scan(
        _stdout_from_request(request, "scan_stdout"),
        int(request.get("scan_exit", 2)),
        mock=bool(request.get("mock")),
    )
    coverage = coverage_decision(
        source,
        scan,
        attest=attest_bytes(source_data),
        scope=request.get("scope", "full"),
        justified_spans=[tuple(item) for item in request.get("justified_spans", [])],
        missing_required=request.get("missing_required"),
        representation=request.get("representation", "text"),
    )
    validation = None
    if "validate_stdout" in request or "validate_stdout_path" in request:
        validation = inspect_validate(
            _stdout_from_request(request, "validate_stdout"),
            int(request.get("validate_exit", 2)),
            mock=bool(request.get("mock")),
        )
    protected = None
    specs = request.get("protected_registry", request.get("protected_specs"))
    if specs is not None:
        protected = compare_protected(
            source,
            candidate,
            specs,
            lifted=request.get("lifted"),
            source_bytes=source_data,
            candidate_bytes=candidate_data,
        )
    file_checks = aggregate_file_checks(
        source,
        candidate,
        coverage,
        source_bytes=source_data,
        candidate_bytes=candidate_data,
        protected=protected,
        validation=validation,
        review=review if isinstance(review, dict) else None,
        scan=scan,
        protected_required=bool(request.get("protected_required")),
        mock=bool(request.get("mock")),
        ignored_inputs=ignored,
    )
    return _emit(
        {
            "role": ROLE,
            "file_status": file_checks["file_status"],
            "scientific_acceptance": False,
            "semantic_review_required": file_checks["semantic_review_required"],
            "coverage": coverage,
            "protected": protected,
            "validation": validation,
            "file_checks": file_checks,
        }
    )


if __name__ == "__main__":
    sys.exit(main())
