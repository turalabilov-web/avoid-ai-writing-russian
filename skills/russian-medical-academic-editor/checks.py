"""Файловые сверки покрытия и защищённых фрагментов.

Помощник не вызывает детектор, не ставит пакеты и не решает, истинно ли
утверждение. Он читает уже полученный JSON и байты копий. Код выхода 0
означает только то, что решение напечатано, а не то, что текст принят.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from bisect import bisect_right
from collections import Counter
from pathlib import Path
from typing import Any, TypedDict

ROLE = "file-check"
# Классы букв склеены в коде: в файле не должно быть латинской буквы внутри русского слова.
_CYR = "А-Яа-яЁё"
_LAT = "A-Za-z"
_LETTERS = _CYR + _LAT
_GROUP_MARK = "АБВ" + "ABV"

_MARKER = re.compile(
    r"^[ \t]*<!--[ \t]*(aiw-ru|avoid-ai-writing):ignore-(start|end)[ \t]*-->[ \t]*$",
    re.MULTILINE,
)
_FENCE = re.compile(r"^(```|~~~)[^\n]*\n[\s\S]*?^\1[^\n]*$", re.MULTILINE)
_FRONT = re.compile(r"^---\n[\s\S]*?\n---(?:\n|$)")
_HEADING = re.compile(r"^#{1,6}[ \t]+.*$", re.MULTILINE)
_TABLE = re.compile(r"^[ \t]*\|.+\|[ \t]*$", re.MULTILINE)
_WORD = re.compile(r"[0-9" + _LETTERS + r"-]+")
_NUMBER = re.compile(r"\d+(?:[.,]\d+)?")
_SIDE = re.compile(
    r"слева|справа|лев(?:ая|ой|ую|ый|ого|ом|ым|ое)|прав(?:ая|ой|ую|ый|ого|ом|ым|ое)",
    re.IGNORECASE,
)
_RISK = re.compile(r"(абсолютн\w*|относительн\w*)\s+риск", re.IGNORECASE)
_UNIT = re.compile(
    r"(\d+(?:[.,]\d+)?)\s*(мкг|мм|см|мг|кг|мл|сут(?:ки|ок)?|час(?:а|ов)?)",
    re.IGNORECASE,
)
_PROCEDURE = re.compile(r"первичн\w*|повторн\w*", re.IGNORECASE)
_DIRECTION = re.compile(r"\b(выше|ниже|больше|меньше)\b", re.IGNORECASE)
_AFTER = re.compile(r"после\s+([" + _LETTERS + r"-]{3,})", re.IGNORECASE)
_GROUP = re.compile(
    r"групп[аеуы]\s+([" + _GROUP_MARK + r"])\b(?:(?!групп)[\s\S]){0,160}?(\d+)\s+из\s+(\d+)",
    re.IGNORECASE,
)

# Пустые вводные и ближайшие к ним служебные слова. Клинические токены сюда не входят.
STYLE_ALLOW = frozenset(
    {
        "следует",
        "отметить",
        "рамках",
        "данной",
        "данном",
        "работы",
        "работа",
        "был",
        "было",
        "были",
        "проведен",
        "проведён",
        "проведена",
        "проведено",
        "анализ",
        "проанализированы",
        "проанализирован",
        "проанализирована",
        "проанализировали",
        "данный",
        "данная",
        "данное",
    }
)
GLUE = frozenset(
    {
        "в",
        "во",
        "с",
        "со",
        "и",
        "а",
        "у",
        "к",
        "о",
        "об",
        "от",
        "по",
        "на",
        "за",
        "до",
        "из",
        "что",
        "это",
        "как",
        "при",
        "для",
        "или",
        "но",
        "же",
        "бы",
        "ли",
        "то",
    }
)


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


class _Located(TypedDict):
    start: int
    section: str
    occurrence: int


def bind_protected(source: str, specs: list[dict[str, Any]]) -> dict[str, Any]:
    """Реестр до правки. Хэш всего файла сюда не подставляется вместо фрагмента."""
    spans = _sections(source)
    items: list[dict[str, Any]] = []
    errors: list[str] = []
    for spec in specs:
        identifier = str(spec["id"])
        exact = spec["exact"]
        if not isinstance(exact, str) or exact == "":
            errors.append(f"{identifier}: пустой фрагмент не регистрируется")
            continue
        hits = _find_all(source, exact)
        described: list[_Located] = []
        for index in hits:
            section = _section_at(spans, index)
            section_hits = [hit for hit in hits if _section_at(spans, hit) == section]
            described.append(
                {
                    "start": index,
                    "section": section,
                    "occurrence": section_hits.index(index),
                }
            )
        wanted_section = spec.get("section")
        wanted_occurrence = spec.get("occurrence")
        chosen = described
        if isinstance(wanted_section, str):
            chosen = [item for item in chosen if item["section"] == wanted_section]
        if wanted_occurrence is not None:
            chosen = [item for item in chosen if item["occurrence"] == wanted_occurrence]
        if len(chosen) != 1:
            errors.append(
                f"{identifier}: в источнике {'нет однозначной привязки' if chosen else 'фрагмент не найден'} "
                f"({len(chosen)} кандидатов)"
            )
            continue
        pick = chosen[0]
        raw = exact.encode("utf-8")
        items.append(
            {
                "id": identifier,
                "exact": exact,
                "sha256": sha256_bytes(raw),
                "byte_length": len(raw),
                "start": pick["start"],
                "end": pick["start"] + len(exact),
                "byte_start": _byte_offset(source, pick["start"]),
                "section": pick["section"],
                "occurrence": pick["occurrence"],
                "count_in_source": source.count(exact),
            }
        )
    items.sort(key=lambda item: item["start"])
    return {
        "role": ROLE,
        "ok": not errors,
        "unverifiable": bool(errors),
        "errors": errors,
        "items": items,
    }


def compare_protected(
    source: str,
    candidate: str,
    specs: list[dict[str, Any]],
    *,
    lifted: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Побайтовая сверка по разделу и номеру вхождения, без поиска «где угодно»."""
    registry = bind_protected(source, specs)
    if registry["unverifiable"]:
        return {
            "role": ROLE,
            "status": "BLOCKED",
            "reasons": registry["errors"],
            "items": [],
            "registry_empty": not specs,
        }
    lifted = lifted or {}
    results: list[dict[str, Any]] = []
    located: list[tuple[int, int, str]] = []
    candidate_spans = _sections(candidate)
    heading_counts = Counter(heading for heading, _, _ in candidate_spans)
    for item in registry["items"]:
        reason = lifted.get(item["id"], "")
        if item["id"] in lifted:
            if not str(reason).strip():
                results.append({"id": item["id"], "status": "BLOCKED", "reason": "снятие защиты без записи решения"})
                continue
            results.append({"id": item["id"], "status": "LIFTED", "reason": reason})
            continue
        if item["section"] and heading_counts[item["section"]] != 1:
            results.append({"id": item["id"], "status": "BLOCKED", "reason": "раздел в копии не однозначен"})
            continue
        section_span = next(
            ((start, end) for heading, start, end in candidate_spans if heading == item["section"]), None
        )
        if section_span is None:
            results.append(
                {
                    "id": item["id"],
                    "status": "ROLLBACK",
                    "reason": "раздел пропал",
                    "elsewhere": item["exact"] in candidate,
                }
            )
            continue
        section_text = candidate[section_span[0] : section_span[1]]
        local_hits = _find_all(section_text, item["exact"])
        source_count = item["count_in_source"]
        candidate_count = candidate.count(item["exact"])
        if item["occurrence"] >= len(local_hits):
            results.append(
                {
                    "id": item["id"],
                    "status": "ROLLBACK",
                    "reason": "фрагмент не найден в своём разделе",
                    "elsewhere": item["exact"] in candidate,
                    "source_count": source_count,
                    "candidate_count": candidate_count,
                }
            )
            continue
        if candidate_count != source_count:
            results.append(
                {
                    "id": item["id"],
                    "status": "ROLLBACK",
                    "reason": "число вхождений изменилось",
                    "source_count": source_count,
                    "candidate_count": candidate_count,
                }
            )
            continue
        absolute = section_span[0] + local_hits[item["occurrence"]]
        piece = candidate[absolute : absolute + len(item["exact"])]
        if piece != item["exact"]:
            results.append({"id": item["id"], "status": "ROLLBACK", "reason": "байты фрагмента отличаются"})
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
                result["status"] = "ROLLBACK"
                result["reason"] = "порядок защищённых фрагментов изменился: " + ", ".join(order_broken)
    statuses = {item["status"] for item in results}
    if "BLOCKED" in statuses:
        status = "BLOCKED"
    elif "ROLLBACK" in statuses:
        status = "ROLLBACK"
    else:
        status = "PASS"
    return {
        "role": ROLE,
        "status": status,
        "reasons": [item.get("reason", "") for item in results if item["status"] != "PASS"],
        "items": results,
        "registry_empty": not specs,
    }


def _tokens(text: str) -> list[str]:
    words = [item.casefold() for item in _WORD.findall(text)]
    return [word for word in words if word not in GLUE and word not in STYLE_ALLOW]


def _lemma(word: str) -> str:
    if len(word) >= 6:
        return word[:6]
    return word


def _sequence(pattern: re.Pattern[str], text: str) -> list[str]:
    return [match.group(0).casefold() for match in pattern.finditer(text)]


def screen_invariants(source: str, candidate: str) -> dict[str, Any]:
    """Узкий список подмен из договора. Молчание списка не доказывает сохранность смысла."""
    breaches: list[dict[str, str]] = []

    def add(kind: str, detail: str) -> None:
        breaches.append({"kind": kind, "detail": detail})

    if _sequence(_SIDE, source) != _sequence(_SIDE, candidate):
        add("laterality", "сторона или латеральность изменилась")
    if _sequence(_RISK, source) != _sequence(_RISK, candidate):
        add("risk_kind", "абсолютный и относительный риск не взаимозаменяемы")
    if _sequence(_UNIT, source) != _sequence(_UNIT, candidate):
        add("unit", "единица при числе изменилась")
    if _sequence(_PROCEDURE, source) != _sequence(_PROCEDURE, candidate):
        add("procedure_order", "первичная и повторная процедура разошлись")
    if _sequence(_DIRECTION, source) != _sequence(_DIRECTION, candidate):
        add("direction", "направление сравнения изменилось")
    if [item.casefold() for item in _AFTER.findall(source)] != [item.casefold() for item in _AFTER.findall(candidate)]:
        add("window", "окно или точка отсчёта после события изменились")
    if _NUMBER.findall(source) != _NUMBER.findall(candidate):
        add("numbers", "последовательность чисел изменилась")
    source_groups = [(item[0].casefold(), item[1], item[2]) for item in _GROUP.findall(source)]
    candidate_groups = [(item[0].casefold(), item[1], item[2]) for item in _GROUP.findall(candidate)]
    if source_groups != candidate_groups:
        add("group_numbers", "связка группы и числа изменилась")
    source_absence = bool(re.search(r"не\s+выявлен\w*|не\s+обнаружен\w*", source, re.IGNORECASE))
    if (
        source_absence
        and re.search(r"эквивалент", candidate, re.IGNORECASE)
        and not re.search(r"эквивалент", source, re.IGNORECASE)
    ):
        add("equivalence", "отсутствие различия переписано как эквивалентность")
    source_causal = (
        bool(re.search(r"ассоциир", source, re.IGNORECASE)),
        bool(re.search(r"увеличива\w*|вызыва\w*|приводил\w*", source, re.IGNORECASE)),
    )
    candidate_causal = (
        bool(re.search(r"ассоциир", candidate, re.IGNORECASE)),
        bool(re.search(r"увеличива\w*|вызыва\w*|приводил\w*", candidate, re.IGNORECASE)),
    )
    if source_causal != candidate_causal and source_causal[0] and candidate_causal[1] and not candidate_causal[0]:
        add("causation", "ассоциация переписана как увеличение, причина или следствие")
    source_status = (
        bool(re.search(r"планир", source, re.IGNORECASE)),
        bool(re.search(r"предварительн", source, re.IGNORECASE)),
        bool(re.search(r"валидир", source, re.IGNORECASE)),
        bool(re.search(r"разработан(?:а|о|ы|ный|ная|ное|ных)?(?![а-яё])", source, re.IGNORECASE)),
    )
    candidate_status = (
        bool(re.search(r"планир", candidate, re.IGNORECASE)),
        bool(re.search(r"предварительн", candidate, re.IGNORECASE)),
        bool(re.search(r"валидир", candidate, re.IGNORECASE)),
        bool(re.search(r"разработан(?:а|о|ы|ный|ная|ное|ных)?(?![а-яё])", candidate, re.IGNORECASE)),
    )
    if (
        source_status != candidate_status
        and (source_status[0] or source_status[1])
        and (candidate_status[2] or candidate_status[3])
    ):
        add("study_status", "план или предварительная проверка переписаны как выполненный результат")
    if re.search(r"не\s+позволя", source, re.IGNORECASE) and not re.search(r"не\s+позволя", candidate, re.IGNORECASE):
        add("modality", "оговорка «не позволяет» снята")
    source_condition = (
        bool(re.search(r"при\s+наличии", source, re.IGNORECASE)),
        bool(re.search(r"независимо\s+от", source, re.IGNORECASE)),
    )
    candidate_condition = (
        bool(re.search(r"при\s+наличии", candidate, re.IGNORECASE)),
        bool(re.search(r"независимо\s+от", candidate, re.IGNORECASE)),
    )
    if source_condition != candidate_condition:
        add("condition", "условие «при наличии» снято или заменено на «независимо от»")
    source_lemmas = [_lemma(word) for word in _tokens(source)]
    candidate_lemmas = [_lemma(word) for word in _tokens(candidate)]
    style_only_delta = source_lemmas == candidate_lemmas
    delta = Counter(source_lemmas)
    delta.subtract(candidate_lemmas)
    return {
        "role": ROLE,
        "breaches": breaches,
        "style_only_delta": style_only_delta,
        "source_content": source_lemmas,
        "candidate_content": candidate_lemmas,
        "lemma_delta": {key: value for key, value in delta.items() if value},
    }


def _review_covers(screen: dict[str, Any], review: dict[str, Any] | None) -> bool:
    if screen["style_only_delta"]:
        return bool(review and review.get("style_only") and str(review.get("note", "")).strip())
    if not review:
        return False
    changes = review.get("token_changes") or []
    if not str(review.get("note", "")).strip() or not review.get("invariants_checked"):
        return False
    covered_removed = Counter(_lemma(item["removed"].casefold()) for item in changes if item.get("removed"))
    covered_added = Counter(_lemma(item["added"].casefold()) for item in changes if item.get("added"))
    source_only = Counter(screen["source_content"])
    candidate_only = Counter(screen["candidate_content"])
    source_extra = source_only - candidate_only
    candidate_extra = candidate_only - source_only
    return source_extra == covered_removed and candidate_extra == covered_added


def decide_delivery(
    source: str,
    candidate: str,
    coverage: dict[str, Any],
    *,
    protected: dict[str, Any] | None = None,
    validation: dict[str, Any] | None = None,
    screen: dict[str, Any] | None = None,
    edit_allowed: bool = False,
    semantic_review: dict[str, Any] | None = None,
    protected_required: bool = False,
    warnings_resolved: list[str] | None = None,
    mock: bool = False,
) -> dict[str, Any]:
    """Итоговая метка диапазона. Формальный ok валидатора её не назначает."""
    text_changed = source != candidate
    screen = screen if screen is not None else screen_invariants(source, candidate)
    reasons: list[str] = []
    covered = bool(coverage.get("full_range_acceptance") or coverage.get("limited_scope_acceptance"))
    result_scope = (
        "full"
        if coverage.get("full_range_acceptance")
        else "limited"
        if coverage.get("limited_scope_acceptance")
        else None
    )
    forbidden = {"NO_EDIT_NEEDED", "APPLIED_AND_VERIFIED"}
    status = "BLOCKED"
    structural_only = coverage.get("disposition") == "LIMITED" and not coverage.get("global_blocked") and not covered
    if mock or (validation and validation.get("mock")) or coverage.get("mock"):
        reasons.append("прогон помечен как mock и не является работой линтера")
    elif protected_required and (protected is None or protected.get("registry_empty")):
        reasons.append("реестр защищённых фрагментов обязателен и пуст")
    elif protected and protected.get("status") == "BLOCKED":
        reasons.extend(protected.get("reasons") or ["защищённый фрагмент нельзя проверить"])
    elif protected and protected.get("status") == "ROLLBACK":
        status = "ROLLBACK"
        reasons.extend(protected.get("reasons") or ["защищённый фрагмент не сохранён"])
    elif screen.get("breaches"):
        status = "ROLLBACK"
        reasons.extend(f"{item['kind']}: {item['detail']}" for item in screen["breaches"])
    elif coverage.get("global_blocked") or not covered:
        reasons.extend(coverage.get("reasons") or ["покрытие не позволяет штатную приёмку"])
        if (
            structural_only
            and not text_changed
            and validation
            and validation.get("schema_ok")
            and validation.get("ok") is True
            and not validation.get("warning_kinds")
        ):
            status = "DETECT_ONLY"
            reasons.append("обычная разметка сохранена, полнота прозы не заявлена")
    elif validation is None or not validation.get("parsed"):
        reasons.append("validate не выполнен или ответ не разобран")
    elif not validation.get("schema_ok"):
        reasons.extend(validation.get("errors") or ["схема validate не сошлась"])
    elif validation.get("exit_code") not in (0, 1) or validation.get("ok") is None:
        reasons.append("validate завершился сбоем")
    elif validation.get("ok") is False:
        status = "ROLLBACK"
        reasons.append("validate вернул ok false")
    else:
        pending = [kind for kind in validation.get("warning_kinds", []) if kind not in set(warnings_resolved or [])]
        if pending:
            status = "ROLLBACK" if text_changed else "BLOCKED"
            reasons.append("не разобраны предупреждения: " + ", ".join(pending))
        elif text_changed and not edit_allowed:
            status = "CANDIDATE_PENDING"
            reasons.append("правка не разрешена автором, в чистовик её не переносят")
        elif text_changed and not _review_covers(screen, semantic_review):
            reasons.append("изменение токенов не объяснено как стилистика и не записано как разрешённая замена")
        elif text_changed:
            checked = (semantic_review or {}).get("invariants_checked") or []
            if not checked:
                reasons.append("для изменённого текста нет списка сверенных инвариантов")
            else:
                status = "APPLIED_AND_VERIFIED"
                forbidden.discard("APPLIED_AND_VERIFIED")
                reasons.append("разрешённая правка прошла файловую сверку; научную истину это не подтверждает")
        else:
            status = "NO_EDIT_NEEDED"
            forbidden.discard("NO_EDIT_NEEDED")
            reasons.append("текст не менялся, машинное покрытие диапазона позволяет no-op")
    if status in {"ROLLBACK", "BLOCKED", "CANDIDATE_PENDING", "DETECT_ONLY"}:
        forbidden.update({"NO_EDIT_NEEDED", "APPLIED_AND_VERIFIED"})
    if result_scope != "full":
        forbidden.add("APPLIED_AND_VERIFIED")
        if status == "APPLIED_AND_VERIFIED":
            status = "BLOCKED"
            reasons.append("применять правку при неполном покрытии всего запрошенного диапазона нельзя")
    full_pass = status in {"NO_EDIT_NEEDED", "APPLIED_AND_VERIFIED"} and result_scope == "full"
    return {
        "role": ROLE,
        "delivery_status": status,
        "full_pass": full_pass,
        "result_scope": result_scope,
        "text_changed": text_changed,
        "reasons": [item for item in reasons if item],
        "forbidden": sorted(forbidden),
        "named_breaches": screen.get("breaches", []),
        "mock": bool(mock or (validation and validation.get("mock"))),
    }


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _emit(payload: dict[str, Any]) -> int:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return 0


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

    protect = sub.add_parser("protect")
    protect.add_argument("--source", required=True)
    protect.add_argument("--candidate", required=True)
    protect.add_argument("--spec", required=True)

    screen = sub.add_parser("screen")
    screen.add_argument("--source", required=True)
    screen.add_argument("--candidate", required=True)

    gate = sub.add_parser("gate")
    gate.add_argument("--request", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "sha256":
        data = Path(args.file).read_bytes()
        return _emit({"role": ROLE, "sha256": sha256_bytes(data), "byte_length": len(data)})
    if args.cmd == "coverage":
        source = _read(args.source)
        spans = []
        for item in args.justified:
            start, end = item.split(":", 1)
            spans.append((int(start), int(end)))
        scan = inspect_scan(Path(args.scan_stdout).read_text(encoding="utf-8"), args.exit_code, mock=args.mock)
        payload = coverage_decision(
            source,
            scan,
            scope=args.scope,
            justified_spans=spans,
            missing_required=args.missing_block,
            representation=args.representation,
        )
        return _emit(payload)
    if args.cmd == "protect":
        specs = json.loads(Path(args.spec).read_text(encoding="utf-8"))
        return _emit(compare_protected(_read(args.source), _read(args.candidate), specs))
    if args.cmd == "screen":
        return _emit(screen_invariants(_read(args.source), _read(args.candidate)))
    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    source = request["source"]
    candidate = request["candidate"]
    scan = inspect_scan(
        request.get("scan_stdout", ""), int(request.get("scan_exit", 2)), mock=bool(request.get("mock"))
    )
    coverage = coverage_decision(
        source,
        scan,
        scope=request.get("scope", "full"),
        justified_spans=[tuple(item) for item in request.get("justified_spans", [])],
        missing_required=request.get("missing_required"),
        representation=request.get("representation", "text"),
    )
    validation = None
    if "validate_stdout" in request:
        validation = inspect_validate(
            request.get("validate_stdout") or "",
            int(request.get("validate_exit", 2)),
            mock=bool(request.get("mock")),
        )
    protected = None
    if request.get("protected_specs") is not None:
        protected = compare_protected(
            source,
            candidate,
            request["protected_specs"],
            lifted=request.get("lifted"),
        )
    decision = decide_delivery(
        source,
        candidate,
        coverage,
        protected=protected,
        validation=validation,
        edit_allowed=bool(request.get("edit_allowed")),
        semantic_review=request.get("semantic_review"),
        protected_required=bool(request.get("protected_required")),
        warnings_resolved=request.get("warnings_resolved"),
        mock=bool(request.get("mock")),
    )
    return _emit(
        {"role": ROLE, "coverage": coverage, "protected": protected, "validation": validation, "delivery": decision}
    )


if __name__ == "__main__":
    sys.exit(main())
