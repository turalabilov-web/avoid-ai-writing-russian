"""Ремонт R1 навыка russian-medical-academic-editor: покрытие, защита, команды.

Синтетические строки. Детектор и валидатор здесь не подменяются: их ответы
читаются как есть, а решение о приёмке принимает файловая сверка навыка.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from aiw_ru.cli import main
from aiw_ru.skills import for_cli, rewrite
from aiw_ru.text import ignored_ranges

ROOT = Path(__file__).parent.parent
SKILL_DIR = ROOT / "skills" / "russian-medical-academic-editor"
CASES = json.loads((ROOT / "tests" / "fixtures" / "medical" / "cases.json").read_text(encoding="utf-8"))
BY_ID = {case["id"]: case for case in CASES["cases"]}


def load_checks() -> Any:
    cache = SKILL_DIR / "__pycache__"
    if cache.exists():
        shutil.rmtree(cache)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    path = SKILL_DIR / "checks.py"
    spec = importlib.util.spec_from_file_location("rmae_checks", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
        if cache.exists():
            shutil.rmtree(cache)
    return module


CHECKS = load_checks()


@pytest.fixture
def quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("AIW_RU_CONFIG", "")


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _scan(text: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str, dict[str, Any]]:
    path = tmp_path / "block.md"
    path.write_text(text, encoding="utf-8")
    code, out, err = _run(["scan", str(path), "--context", "vak", "--no-model", "--json"], capsys)
    assert err == ""
    return code, out, json.loads(out)


def _validate(before: str, after: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    original = tmp_path / "01_ORIGINAL.md"
    edited = tmp_path / "03_CLEAN_COPY.md"
    original.write_text(before, encoding="utf-8")
    edited.write_text(after, encoding="utf-8")
    code, out, err = _run(["validate", str(original), str(edited), "--context", "vak", "--json"], capsys)
    assert err == ""
    return code, out


def _delivery(
    source: str,
    candidate: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    *,
    specs: list[dict[str, Any]] | None = None,
    edit_allowed: bool = False,
    review: dict[str, Any] | None = None,
    protected_required: bool = False,
    scope: str = "full",
    justified: list[tuple[int, int]] | None = None,
    missing_required: list[str] | None = None,
    representation: str = "text",
    warnings_resolved: list[str] | None = None,
    mock_scan: str | None = None,
    mock_scan_exit: int = 0,
    mock_validate: str | None = None,
    mock_validate_exit: int = 0,
) -> dict[str, Any]:
    if mock_scan is None:
        scan_exit, scan_stdout, _report = _scan(source, tmp_path, capsys)
    else:
        scan_exit, scan_stdout = mock_scan_exit, mock_scan
    scan = CHECKS.inspect_scan(scan_stdout, scan_exit, mock=mock_scan is not None)
    coverage = CHECKS.coverage_decision(
        source,
        scan,
        scope=scope,
        justified_spans=justified,
        missing_required=missing_required,
        representation=representation,
    )
    if mock_validate is None and scan.get("schema_ok"):
        validate_exit, validate_stdout = _validate(source, candidate, tmp_path, capsys)
        validation = CHECKS.inspect_validate(validate_stdout, validate_exit)
    elif mock_validate is not None:
        validation = CHECKS.inspect_validate(mock_validate, mock_validate_exit, mock=True)
    else:
        validation = None
    protected = None if specs is None else CHECKS.compare_protected(source, candidate, specs)
    ignored: list[str] = []
    if edit_allowed:
        ignored.append("edit_allowed")
    if warnings_resolved is not None:
        ignored.append("warnings_resolved")
    if review is not None and "source_sha256" not in review:
        ignored.append("semantic_review")
    file_checks = CHECKS.aggregate_file_checks(
        source,
        candidate,
        coverage,
        protected=protected,
        validation=validation,
        review=review,
        scan=scan,
        protected_required=protected_required,
        mock=mock_scan is not None or mock_validate is not None,
        ignored_inputs=ignored,
    )
    return {
        "scan_exit": scan_exit,
        "scan": scan,
        "coverage": coverage,
        "validation": validation,
        "protected": protected,
        "file_checks": file_checks,
    }


LEGACY_DECLARATION = {
    "style_only": True,
    "note": "снята пустая вводная, клинические токены сверены",
    "invariants_checked": ["числа", "диагноз", "дизайн"],
    "token_changes": [],
}


def test_helper_uses_stdlib_only() -> None:
    """помощник не импортирует детектор и сторонние пакеты и не классифицирует смысл"""
    text = (SKILL_DIR / "checks.py").read_text(encoding="utf-8")
    assert "aiw_ru" not in text
    assert "import pydantic" not in text and "import regex" not in text
    for token in (
        "screen_invariants",
        "STYLE_ALLOW",
        "style_only_delta",
        "_lemma",
        "_review_covers",
        "semantic_equivalent",
        "APPLIED_AND_VERIFIED",
        "decide_delivery",
        "read_text",
    ):
        assert token not in text, token
    with pytest.raises(SystemExit):
        CHECKS.main(["screen", "--source", "a", "--candidate", "b"])


def test_marker_ranges_match_detector() -> None:
    """учёт пометок совпадает с ignored_ranges, сам детектор не переписан"""
    samples = [
        "<!-- aiw-ru:ignore-start -->\nСкрытый абзац.\n<!-- aiw-ru:ignore-end -->\n",
        "Видимое предложение.\n\n<!-- avoid-ai-writing:ignore-start -->\nСкрыто до конца.\n",
        (
            "В исследование включили 48 пациентов.\n"
            "<!-- aiw-ru:ignore-start -->\nОписание одного блока.\n"
            "<!-- aiw-ru:ignore-start -->\nОписание вложенного блока.\n"
            "<!-- aiw-ru:ignore-end -->\nОписание внешнего блока.\n"
            "<!-- aiw-ru:ignore-end -->\nНаблюдение продолжалось 30 суток.\n"
        ),
        "<!-- aiw-ru:ignore-end -->\nОткрытая проза остаётся видимой.\n",
        "Видимо.\n\n```text\n<!-- aiw-ru:ignore-start -->\nпример пометки\n<!-- aiw-ru:ignore-end -->\n```\n",
    ]
    for text in samples:
        regions = [(item["start"], item["end"]) for item in CHECKS.marker_inventory(text)["regions"]]
        assert regions == ignored_ranges(text)


def test_empty_and_whitespace_are_blocked(tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None) -> None:
    """C11 и пробельный файл: exit 0 и ноль слов не становятся полной приёмкой"""
    for source in ("", " \t\n\n"):
        before = source.encode("utf-8")
        result = _delivery(source, source, tmp_path, capsys)
        assert result["scan_exit"] == 0
        assert result["scan"]["words"] == 0
        assert result["coverage"]["false_clean"] is True
        assert result["coverage"]["full_range_acceptance"] is False
        assert result["file_checks"]["file_status"] == "BLOCKED"
        assert result["file_checks"]["full_range_file_pass"] is False
        assert result["file_checks"]["scientific_acceptance"] is False
        assert source.encode("utf-8") == before


def test_fully_ignored_prose_is_blocked(tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None) -> None:
    """C12: нулевое покрытие при exit 0 не даёт NO_EDIT_NEEDED"""
    source = (
        "<!-- aiw-ru:ignore-start -->\n"
        "Следует отметить, что в рамках данной работы был проведён анализ историй болезни 48 пациентов.\n"
        "<!-- aiw-ru:ignore-end -->\n"
    )
    result = _delivery(source, source, tmp_path, capsys)
    assert result["scan_exit"] == 0
    assert result["scan"]["words"] == 0
    assert result["scan"]["ignored_regions"] == 1
    assert result["coverage"]["exclusions"]
    assert "aiw-ru" in result["coverage"]["exclusions"][0]["family"]
    assert result["file_checks"]["full_range_file_pass"] is False
    assert result["file_checks"]["file_status"] == "BLOCKED"
    assert result["file_checks"]["scientific_acceptance"] is False
    assert "<!-- aiw-ru:ignore-start -->" in source


def test_partial_ignore_limits_scope(tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None) -> None:
    """C13: частичное исключение не закрывает весь диапазон"""
    source = (
        "В исследование включили 48 пациентов.\n\n"
        "<!-- aiw-ru:ignore-start -->\n"
        "Следует отметить, что в рамках данной работы был проведён анализ историй болезни.\n"
        "<!-- aiw-ru:ignore-end -->\n"
    )
    blocked = _delivery(source, source, tmp_path, capsys)
    assert blocked["scan"]["words"] == 5
    assert blocked["scan"]["ignored_regions"] == 1
    assert blocked["file_checks"]["file_status"] == "BLOCKED"
    assert blocked["file_checks"]["full_range_file_pass"] is False
    span = (blocked["coverage"]["exclusions"][0]["start"], blocked["coverage"]["exclusions"][0]["end"])
    limited = _delivery(source, source, tmp_path, capsys, scope="limited", justified=[span])
    assert limited["coverage"]["full_range_acceptance"] is False
    assert limited["coverage"]["limited_scope_acceptance"] is True
    assert limited["file_checks"]["file_status"] == "FILE_CHECKS_PASS"
    assert limited["file_checks"]["full_range_file_pass"] is False
    assert limited["file_checks"]["result_scope"] == "limited"
    assert limited["file_checks"]["text_changed"] is False
    assert limited["file_checks"]["scientific_acceptance"] is False
    assert "NO_EDIT_NEEDED" not in json.dumps(limited["file_checks"])


def test_unclosed_nested_and_ordinary_markup(tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None) -> None:
    """вторая семья пометок, вложенность и обычный код не прячут дыру и не блокируют зря"""
    unclosed = (
        "В исследование включили 48 пациентов.\n\n"
        "<!-- avoid-ai-writing:ignore-start -->\n"
        "Следует отметить, что в рамках работы анализировали истории болезни.\n"
    )
    result = _delivery(unclosed, unclosed, tmp_path, capsys)
    assert result["coverage"]["unclosed"] is True
    assert result["coverage"]["exclusions"][0]["family"] == "avoid-ai-writing"
    assert result["file_checks"]["full_range_file_pass"] is False
    nested = (
        "В исследование включили 48 пациентов.\n"
        "<!-- aiw-ru:ignore-start -->\nОписание одного блока.\n"
        "<!-- aiw-ru:ignore-start -->\nОписание вложенного блока.\n"
        "<!-- aiw-ru:ignore-end -->\nОписание внешнего блока.\n"
        "<!-- aiw-ru:ignore-end -->\nНаблюдение продолжалось 30 суток.\n"
    )
    nested_result = _delivery(nested, nested, tmp_path, capsys)
    assert nested_result["coverage"]["nested"] is True
    assert len(nested_result["coverage"]["exclusions"]) == 1
    assert nested_result["scan"]["words"] > 0
    assert nested_result["file_checks"]["full_range_file_pass"] is False
    fenced = "В исследование включили 48 пациентов.\n\n```text\n<!-- aiw-ru:ignore-start -->\nпример\n<!-- aiw-ru:ignore-end -->\n```\n"
    fenced_result = _delivery(fenced, fenced, tmp_path, capsys)
    assert fenced_result["coverage"]["exclusions"] == []
    assert fenced_result["coverage"]["full_range_acceptance"] is True
    assert fenced_result["file_checks"]["file_status"] == "FILE_CHECKS_PASS"
    assert fenced_result["file_checks"]["full_range_file_pass"] is True
    assert fenced_result["file_checks"]["semantic_review_required"] is False
    code_only = "```text\nтолько код без прозы\n```\n"
    code_result = _delivery(code_only, code_only, tmp_path, capsys)
    assert code_result["coverage"]["global_blocked"] is False
    assert code_result["file_checks"]["file_status"] == "FILE_CHECKS_PASS"
    assert code_result["file_checks"]["result_scope"] == "structural"
    assert code_result["file_checks"]["full_range_file_pass"] is False


def test_schema_rejects_empty_object_and_wrong_types() -> None:
    """синтаксически годный JSON неправильной формы не становится отчётом"""
    empty = CHECKS.inspect_scan("{}", 0, mock=True)
    assert empty["schema_ok"] is False
    assert any("score" in item for item in empty["errors"])
    assert CHECKS.inspect_scan("[]", 0, mock=True)["parsed"] is False
    broken = CHECKS.inspect_validate('{"ok":"true","violations":[],"warnings":[]}', 0, mock=True)
    assert broken["schema_ok"] is False
    assert any(item.startswith("ok:") for item in broken["errors"])
    assert any(item.startswith("swappedNumbers:") for item in broken["errors"])
    profile = {
        "score": 0,
        "issues": [],
        "stats": {"words": 1, "contextMode": "general"},
        "meta": {"schema": 1},
    }
    wrong = CHECKS.inspect_scan(json.dumps(profile), 0, mock=True)
    assert wrong["schema_ok"] is False
    profile["stats"]["contextMode"] = "academic"
    profile["classifier"] = {"name": "transformer"}
    classified = CHECKS.inspect_scan(json.dumps(profile), 0, mock=True)
    assert classified["classifier_present"] is True
    assert classified["schema_ok"] is False
    missing_words = {
        "score": 0,
        "issues": [],
        "stats": {"contextMode": "academic"},
        "meta": {"schema": 1},
    }
    absent = CHECKS.inspect_scan(json.dumps(missing_words), 0, mock=True)
    assert any(item.startswith("stats.words:") for item in absent["errors"])
    present_empty = {
        "score": 0,
        "issues": [],
        "stats": {"words": 3, "contextMode": "academic", "ignoredRegions": 0},
        "meta": {"schema": 1},
    }
    parsed = CHECKS.inspect_scan(json.dumps(present_empty), 0, mock=True)
    assert parsed["schema_ok"] is True
    assert parsed["ignored_regions"] == 0


def test_mock_schema_cannot_pass_gate() -> None:
    """mock, в том числе пустой объект, не получает штатную приёмку"""
    source = "В исследование включили 48 пациентов."
    scan = CHECKS.inspect_scan("{}", 0, mock=True)
    coverage = CHECKS.coverage_decision(source, scan)
    file_checks = CHECKS.aggregate_file_checks(source, source, coverage, mock=True)
    assert file_checks["mock"] is True
    assert file_checks["file_status"] == "BLOCKED"
    assert file_checks["full_range_file_pass"] is False
    assert file_checks["scientific_acceptance"] is False


def test_protected_wording_rejects_validate_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None
) -> None:
    """C14: ok true не сохраняет изменённую цель"""
    source = (
        "# Цель исследования\n"
        "Оценить связь длительности наблюдения с повторными госпитализациями.\n\n"
        "В исследование включили 48 пациентов.\n"
    )
    candidate = source.replace("Оценить", "Изучить", 1)
    specs = [
        {
            "id": "goal",
            "exact": "# Цель исследования\nОценить связь длительности наблюдения с повторными госпитализациями.",
        }
    ]
    result = _delivery(source, candidate, tmp_path, capsys, specs=specs, protected_required=True, edit_allowed=True)
    assert result["validation"]["ok"] is True
    assert result["validation"]["exit_code"] == 0
    assert result["protected"]["status"] == "FAIL"
    assert result["protected"]["failure_class"] == "protected_bytes"
    assert result["file_checks"]["file_status"] == "FILE_CHECKS_FAIL"
    assert result["file_checks"]["scientific_acceptance"] is False


def test_duplicate_order_and_whitespace_are_not_substring_checks() -> None:
    """одинаковая строка в другом месте, порядок, дубль и пробел не проходят"""
    repeated = "# Цель\nОценить частоту осложнений.\n\n# Методы\nОценить частоту осложнений.\n"
    changed = "# Цель\nИзучить частоту осложнений.\n\n# Методы\nОценить частоту осложнений.\n"
    exact = "# Цель\nОценить частоту осложнений."
    compared = CHECKS.compare_protected(repeated, changed, [{"id": "goal", "exact": exact}])
    assert compared["status"] == "FAIL"
    assert "Оценить частоту осложнений." in changed
    ordered = "# Цель\nОценить частоту осложнений.\n\n# Ограничения\nДизайн ретроспективный.\n"
    swapped = "# Ограничения\nДизайн ретроспективный.\n\n# Цель\nОценить частоту осложнений.\n"
    specs = [
        {"id": "goal", "exact": "# Цель\nОценить частоту осложнений."},
        {"id": "limit", "exact": "# Ограничения\nДизайн ретроспективный."},
    ]
    assert CHECKS.compare_protected(ordered, swapped, specs)["status"] == "FAIL"
    duplicated_source = "# Цель\nОценить частоту осложнений.\n"
    duplicated = duplicated_source + "Оценить частоту осложнений.\n"
    assert (
        CHECKS.compare_protected(
            duplicated_source, duplicated, [{"id": "goal-line", "exact": "Оценить частоту осложнений."}]
        )["status"]
        == "FAIL"
    )
    spaced = "# Цель\nОценить  частоту осложнений.\n"
    assert (
        CHECKS.compare_protected(
            duplicated_source, spaced, [{"id": "goal", "exact": "# Цель\nОценить частоту осложнений."}]
        )["status"]
        == "FAIL"
    )


def test_shifted_protected_block_allows_neighbor_edit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None
) -> None:
    """правка предыдущего абзаца сдвигает смещение и не ломает байты защиты"""
    source = "# Методы\nСледует отметить, что проанализировали 48 историй болезни.\n\n# Ограничения\nДизайн ретроспективный.\n"
    candidate = "# Методы\nПроанализировали 48 историй болезни.\n\n# Ограничения\nДизайн ретроспективный.\n"
    specs = [{"id": "limit", "exact": "# Ограничения\nДизайн ретроспективный."}]
    result = _delivery(
        source,
        candidate,
        tmp_path,
        capsys,
        specs=specs,
        protected_required=True,
        edit_allowed=True,
        review=LEGACY_DECLARATION,
    )
    assert result["validation"]["ok"] is True
    item = result["protected"]["items"][0]
    assert item["status"] == "PASS"
    assert item["shifted"] is True
    assert item["sha256"] == CHECKS.sha256_bytes(specs[0]["exact"].encode("utf-8"))
    checks = result["file_checks"]
    assert checks["file_status"] == "FILE_CHECKS_PASS"
    assert checks["semantic_review_required"] is True
    assert checks["scientific_acceptance"] is False
    assert checks["review_binding"]["bound"] is False
    assert checks["review_binding"]["legacy_declaration"] is True
    assert "APPLIED_AND_VERIFIED" not in json.dumps(checks)


@pytest.mark.parametrize(
    ("source", "candidate"),
    [
        (
            "В ретроспективной выборке наличие сопутствующего заболевания ассоциировалось с более длительной госпитализацией.",
            "В ретроспективной выборке сопутствующее заболевание увеличивало продолжительность госпитализации.",
        ),
        (
            "Планируется разработать критерии оценки риска послеоперационных осложнений и предварительно проверить их на исходной выборке.",
            "Разработаны и независимо валидированы критерии оценки риска послеоперационных осложнений.",
        ),
        (
            "В группе А после операции серому выявили у 3 из 30 пациентов, в группе Б — у 6 из 30. Различия могли быть связаны с исходными характеристиками пациентов.",
            "В группе А после операции серому выявили у 6 из 30 пациентов, в группе Б — у 3 из 30. Различия могли быть связаны с исходными характеристиками пациентов.",
        ),
        ("При КТ выявлен абсцесс слева от сигмовидной кишки.", "При КТ выявлен абсцесс справа от сигмовидной кишки."),
        (
            "В группе А абсолютный риск осложнений составил 12%.",
            "В группе А относительный риск осложнений составил 12%.",
        ),
        ("Статистически значимых различий не выявлено.", "Эквивалентность методов установлена."),
        (
            "В исследование включали пациентов с абсцессами диаметром более 3 см.",
            "В исследование включали пациентов с абсцессами диаметром более 3 мм.",
        ),
        ("Исходы оценивали через 30 суток после дренирования.", "Исходы оценивали через 30 суток после выписки."),
        (
            "Неэффективность первичного дренирования зарегистрирована у 12 пациентов.",
            "Неэффективность повторного дренирования зарегистрирована у 12 пациентов.",
        ),
        (
            "При более крупных абсцессах частота повторных вмешательств была выше.",
            "При более крупных абсцессах частота повторных вмешательств была ниже.",
        ),
        (
            "Чрескожное дренирование рассматривали при наличии безопасного доступа.",
            "Чрескожное дренирование рассматривали независимо от наличия безопасного доступа.",
        ),
    ],
)
def test_named_invariant_is_not_classified_by_helper(
    source: str, candidate: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None
) -> None:
    """опасная пара не получает машинную приёмку; вето редактора проверяет контракт R2"""
    result = _delivery(source, candidate, tmp_path, capsys, edit_allowed=True, review=LEGACY_DECLARATION)
    checks = result["file_checks"]
    assert checks["scientific_acceptance"] is False
    assert checks["semantic_review_required"] is True
    assert checks["review_binding"]["bound"] is False
    assert checks["review_binding"]["legacy_declaration"] is True
    dumped = json.dumps(checks, ensure_ascii=False)
    assert "style_only_delta" not in dumped
    assert "APPLIED_AND_VERIFIED" not in dumped
    assert "screen" not in result
    assert result["validation"]["parsed"] is True


def test_unit_warning_stays_blocking_when_marked_resolved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None
) -> None:
    """запись «предупреждение разобрано» не отменяет смену единицы"""
    source = "В исследование включали пациентов с абсцессами диаметром более 3 см."
    candidate = "В исследование включали пациентов с абсцессами диаметром более 3 мм."
    result = _delivery(
        source,
        candidate,
        tmp_path,
        capsys,
        edit_allowed=True,
        review=LEGACY_DECLARATION,
        warnings_resolved=["единица"],
    )
    assert result["validation"]["ok"] is True
    assert "единица" in result["validation"]["warning_kinds"]
    assert "warnings_resolved" in result["file_checks"]["ignored_inputs"]
    assert result["file_checks"]["file_status"] == "FILE_CHECKS_FAIL"
    assert result["file_checks"]["scientific_acceptance"] is False


def test_changed_number_is_rollback(tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None) -> None:
    """замена 48 на 84 отвергается и валидатором, и сверкой чисел"""
    source = "В исследование включили 48 пациентов.\n"
    candidate = "В исследование включили 84 пациентов.\n"
    result = _delivery(source, candidate, tmp_path, capsys, edit_allowed=True, review=LEGACY_DECLARATION)
    assert result["validation"]["ok"] is False
    assert result["validation"]["exit_code"] == 1
    assert result["file_checks"]["file_status"] == "FILE_CHECKS_FAIL"
    assert result["file_checks"]["scientific_acceptance"] is False


def test_noop_and_allowed_edits(tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None) -> None:
    """B01 остаётся no-op, B04 и соседний абзац B08/B12 проходят оба контроля"""
    b01 = BY_ID["B01"]["source"]
    untouched = _delivery(b01, b01, tmp_path, capsys)
    assert untouched["file_checks"]["file_status"] == "FILE_CHECKS_PASS"
    assert untouched["file_checks"]["full_range_file_pass"] is True
    assert untouched["file_checks"]["text_changed"] is False
    assert untouched["file_checks"]["semantic_review_required"] is False
    assert untouched["file_checks"]["scientific_acceptance"] is False
    b04 = BY_ID["B04"]
    edited = _delivery(b04["source"], b04["candidate"], tmp_path, capsys, edit_allowed=True, review=LEGACY_DECLARATION)
    assert edited["validation"]["ok"] is True
    assert edited["file_checks"]["file_status"] == "FILE_CHECKS_PASS"
    assert edited["file_checks"]["semantic_review_required"] is True
    assert edited["file_checks"]["scientific_acceptance"] is False
    assert edited["file_checks"]["review_binding"]["bound"] is False
    b08 = BY_ID["B08"]["source"]
    b08_candidate = b08.replace(
        "Следует отметить, что анализ включает 48 историй болезни.",
        "Анализ включает 48 историй болезни.",
        1,
    )
    specs = [{"id": f"p{i}", "exact": exact} for i, exact in enumerate(BY_ID["B08"]["protected_exact"])]
    kept = _delivery(
        b08,
        b08_candidate,
        tmp_path,
        capsys,
        specs=specs,
        protected_required=True,
        edit_allowed=True,
        review=LEGACY_DECLARATION,
    )
    assert kept["protected"]["status"] == "PASS"
    assert kept["file_checks"]["file_status"] == "FILE_CHECKS_PASS"
    assert kept["file_checks"]["scientific_acceptance"] is False
    b12 = BY_ID["B12"]["source"]
    b12_candidate = b12.replace(
        "Следует отметить, что проанализированы 48 историй болезни.",
        "Проанализированы 48 историй болезни.",
        1,
    )
    specs = [{"id": f"p{i}", "exact": exact} for i, exact in enumerate(BY_ID["B12"]["protected_exact"])]
    composite = _delivery(
        b12,
        b12_candidate,
        tmp_path,
        capsys,
        specs=specs,
        protected_required=True,
        edit_allowed=True,
        review=LEGACY_DECLARATION,
    )
    assert composite["protected"]["status"] == "PASS"
    assert "48" in b12_candidate
    assert composite["file_checks"]["scientific_acceptance"] is False
    assert composite["file_checks"]["semantic_review_required"] is True


def test_author_token_change_is_explicit(tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None) -> None:
    """список токенов и галочка не прикрывают замену; полная запись тоже не принимает смысл"""
    source = BY_ID["B03"]["source"]
    candidate = BY_ID["B03"]["candidate"]
    missing = _delivery(source, candidate, tmp_path, capsys, edit_allowed=True, review=LEGACY_DECLARATION)
    assert missing["file_checks"]["scientific_acceptance"] is False
    assert missing["file_checks"]["review_binding"]["bound"] is False
    token_review = {
        "style_only": False,
        "note": "автор разрешил одну замену повтора",
        "invariants_checked": ["осложнения", "операция"],
        "token_changes": [{"removed": "описаны", "added": "приведены"}],
    }
    tokens = _delivery(source, candidate, tmp_path, capsys, edit_allowed=True, review=token_review)
    assert tokens["validation"]["ok"] is True
    assert tokens["file_checks"]["review_binding"]["bound"] is False
    assert tokens["file_checks"]["scientific_acceptance"] is False
    bound = CHECKS.bind_review(
        {
            "source_sha256": CHECKS.sha256_bytes(source.encode("utf-8")),
            "candidate_sha256": CHECKS.sha256_bytes(candidate.encode("utf-8")),
            "decision": "ACCEPT",
            "changes": [
                {
                    "before": source,
                    "after": candidate,
                    "locator": "предложение 1",
                    "defect": "повтор «описаны»",
                    "permission": "автор разрешил одну замену",
                    "source_claim": "Описаны осложнения после операции.",
                    "candidate_claim": "Приведены те же осложнения после той же операции.",
                }
            ],
        },
        CHECKS.sha256_bytes(source.encode("utf-8")),
        CHECKS.sha256_bytes(candidate.encode("utf-8")),
    )
    assert bound["bound"] is True
    assert bound["scientific_acceptance"] is False
    anatomy_source = "В исследование включили 48 пациентов с паховыми грыжами."
    anatomy = anatomy_source.replace("паховыми", "бедренными")
    hidden = _delivery(anatomy_source, anatomy, tmp_path, capsys, edit_allowed=True, review=LEGACY_DECLARATION)
    assert hidden["file_checks"]["scientific_acceptance"] is False
    assert hidden["file_checks"]["review_binding"]["legacy_declaration"] is True


def test_missing_cli_file_and_bad_utf8(tmp_path: Path, capsys: pytest.CaptureFixture[str], quiet: None) -> None:
    """реальные сбои ввода: отсутствующий файл и битый UTF-8"""
    missing = tmp_path / "нет-файла.md"
    code, out, err = _run(["scan", str(missing), "--context", "vak", "--no-model", "--json"], capsys)
    assert code == 2
    assert out.strip() == ""
    assert err
    broken = tmp_path / "broken.md"
    broken.write_bytes("В исследование ".encode() + b"\xff\xfe")
    code, out, err = _run(["scan", str(broken), "--context", "vak", "--no-model", "--json"], capsys)
    assert code == 2
    assert out.strip() == ""
    scan = CHECKS.inspect_scan("", code)
    coverage = CHECKS.coverage_decision("В исследование включили 48 пациентов.", scan)
    file_checks = CHECKS.aggregate_file_checks(
        "В исследование включили 48 пациентов.",
        "В исследование включили 48 пациентов.",
        coverage,
    )
    assert file_checks["file_status"] == "BLOCKED"
    assert file_checks["mock"] is False


def test_unresolved_warning_blocks_acceptance() -> None:
    """код 0 и ok true с неразобранным предупреждением не принимаются"""
    source = "В группе А наблюдали 30 пациентов."
    payload = {
        "ok": True,
        "violations": [],
        "warnings": [{"kind": "единица", "detail": "пример предупреждения"}],
        "swappedNumbers": [],
        "issuesBefore": 0,
        "issuesAfter": 0,
        "meta": {"schema": 1},
    }
    validation = CHECKS.inspect_validate(json.dumps(payload), 0, mock=True)
    scan = CHECKS.inspect_scan(
        json.dumps(
            {
                "score": 0,
                "issues": [],
                "stats": {"words": 5, "contextMode": "academic"},
                "meta": {"schema": 1},
            }
        ),
        0,
        mock=True,
    )
    coverage = CHECKS.coverage_decision(source, scan)
    file_checks = CHECKS.aggregate_file_checks(source, source, coverage, validation=validation, scan=scan, mock=True)
    assert file_checks["file_status"] == "BLOCKED"
    assert file_checks["mock"] is True
    plain_validation = CHECKS.inspect_validate(json.dumps(payload), 0, mock=False)
    plain_scan = CHECKS.inspect_scan(
        json.dumps(
            {
                "score": 0,
                "issues": [],
                "stats": {"words": 5, "contextMode": "academic"},
                "meta": {"schema": 1},
            }
        ),
        0,
        mock=False,
    )
    plain_coverage = CHECKS.coverage_decision(source, plain_scan)
    plain = CHECKS.aggregate_file_checks(source, source, plain_coverage, validation=plain_validation, scan=plain_scan)
    assert plain["mock"] is False
    assert plain["file_status"] == "FILE_CHECKS_FAIL"
    assert "единица" in plain["warning_kinds"]


def test_extraction_gap_blocks_full_range() -> None:
    """нет текста обязательной страницы: полный диапазон блокируется, текст не дописывается"""
    source = "Проверена только первая страница."
    scan = CHECKS.inspect_scan(
        json.dumps(
            {
                "score": 0,
                "issues": [],
                "stats": {"words": 4, "contextMode": "academic"},
                "meta": {"schema": 1},
            }
        ),
        0,
        mock=True,
    )
    coverage = CHECKS.coverage_decision(source, scan, missing_required=["страница 2"], representation="extracted")
    assert coverage["global_blocked"] is True
    assert "страница 2" in " ".join(coverage["reasons"])
    file_checks = CHECKS.aggregate_file_checks(source, source, coverage, mock=True)
    assert file_checks["full_range_file_pass"] is False
    assert file_checks["file_status"] == "BLOCKED"


def test_commands_are_consistent_raw_and_rendered() -> None:
    """сырой текст и вывод aiw-ru skill не противоречат друг другу"""
    skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    runtime = (SKILL_DIR / "references" / "runtime-and-artifacts.md").read_text(encoding="utf-8")
    assert 'uv run --locked --project "$PROJECT_ROOT"' in skill
    assert 'uv run --locked --project "$PROJECT_ROOT"' in runtime
    assert "command -v aiw-ru" in skill
    assert "Get-Command aiw-ru" in skill
    rendered_skill = for_cli(skill, "russian-medical-academic-editor")
    rendered_runtime = rewrite(runtime, "russian-medical-academic-editor")
    for rendered in (rendered_skill, rendered_runtime):
        assert "repo-only" not in rendered
        assert "uv run" not in rendered
        assert "../" not in rendered
        assert "command -v aiw-ru" not in rendered
        assert 'aiw-ru scan "$INPUT" --context vak --no-model --json' in rendered
        assert 'aiw-ru validate "$ORIGINAL" "$CLEAN" --context vak --json' in rendered
    assert "Если установленной команды нет" not in rendered_skill
    assert "Если установленной команды нет" not in rendered_runtime
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "### Кандидат russian-medical-academic-editor" in readme
    assert "Установка в ChatGPT этой инструкцией не утверждается." in readme
    assert "2.10.1" in readme


def test_scan_from_another_directory_with_spaces(tmp_path: Path) -> None:
    """абсолютный путь читается из чужого каталога, lockfile проекта не меняется"""
    folder = tmp_path / "with space"
    folder.mkdir()
    target = folder / "note.md"
    text = "В исследование включили 48 пациентов."
    target.write_text(text, encoding="utf-8")
    lock_before = (ROOT / "uv.lock").read_bytes()
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env["AIW_RU_CONFIG"] = ""
    proc = subprocess.run(
        [sys.executable, "-m", "aiw_ru", "scan", str(target), "--context", "vak", "--no-model", "--json"],
        cwd=folder,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["stats"]["contextMode"] == "academic"
    assert report["stats"]["words"] > 0
    assert (ROOT / "uv.lock").read_bytes() == lock_before
    uv = shutil.which("uv")
    assert uv, "uv нужен для проверки locked-запуска"
    locked = subprocess.run(
        [
            uv,
            "run",
            "--offline",
            "--locked",
            "--project",
            str(ROOT),
            "aiw-ru",
            "scan",
            str(target),
            "--context",
            "vak",
            "--no-model",
            "--json",
        ],
        cwd=folder,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert locked.returncode == 0, locked.stderr
    assert json.loads(locked.stdout)["stats"]["words"] == report["stats"]["words"]
    assert (ROOT / "uv.lock").read_bytes() == lock_before
