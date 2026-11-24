# RMAE R2 — офлайн-испытание в Work

Пакет содержит исходный архив R2, неизменённый, и ровно десять wheel-файлов с SHA-256 из оригинального uv.lock для CPython 3.12/Linux x86_64. Не устанавливать глобально. Не изменять навык, исходники, lockfile. Не обращаться к сети. Не устанавливать модели. Это **source-run с точными версиями зависимостей**, не `uv sync --locked` и не установленный дистрибутив aiw-ru. Hatchling для этого пути не нужен. Если любой шаг не удаётся, остановиться и зафиксировать BLOCKED.

## 1. Подготовка
Распаковать внешний архив в новый временный каталог, перейти в него; `sha256sum -c SHA256SUMS.txt`. Сверить каждый wheel также с WHEEL_MANIFEST.json. Проверить `python3 --version`, `uv --version`, архитектуру и соответствие wheel tags. Сохранить исходные архивы.

```bash
BASE="$PWD"
mkdir "$BASE/runtime"
python3 -m zipfile -e "$BASE/RMAE_R2_CLI_RUNTIME_BUNDLE.zip" "$BASE/runtime"
(cd "$BASE/runtime" && sha256sum -c SHA256SUMS.txt)
PYTHON=$(command -v python3)
export UV_PYTHON_DOWNLOADS=never
export UV_CACHE_DIR="$BASE/empty-uv-cache"
mkdir "$UV_CACHE_DIR"
uv venv --offline --python "$PYTHON" "$BASE/env"
uv pip install --offline --no-index --find-links "$BASE/wheelhouse" --python "$BASE/env/bin/python" --require-hashes --only-binary :all: -r "$BASE/runtime/requirements-runtime-lock.txt"
uv pip check --python "$BASE/env/bin/python"
```

Не продолжать при ненулевом коде или несовпадении хэшей. С помощью importlib.metadata.version проверить ВСЕ десять версий в env, пути импортируемых модулей и Python. Сверить пять файлов установленного навыка с runtime/source/skills/russian-medical-academic-editor. Не путать совпадение версии с происхождением.

## 2. Проба CLI
Сделать новый рабочий каталог, записать синтетический текст «В исследование включили 48 пациентов. После операции наблюдение продолжалось 30 суток.» как UTF-8 и точную копию. Использовать абсолютные пути. Для каждого запуска отдельно записать stdout, stderr, exit code, argv.

```bash
export PYTHONPATH="$BASE/runtime/source/src"
"$BASE/env/bin/python" -m aiw_ru --version
"$BASE/env/bin/python" -m aiw_ru scan "$ORIGINAL" --context vak --no-model --json
"$BASE/env/bin/python" -m aiw_ru validate "$ORIGINAL" "$COPY" --context vak --json
python3 "$INSTALLED_SKILL/checks.py" sha256 "$ORIGINAL"
python3 "$INSTALLED_SKILL/checks.py" coverage --source "$ORIGINAL" --scan-stdout "$SCAN_JSON" --exit-code "$SCAN_EXIT"
```

Задать ORIGINAL, COPY, INSTALLED_SKILL, SCAN_JSON, SCAN_EXIT по фактическим путям/коду. Проверить JSON scan: stats.words>0, contextMode=academic, classifier отсутствует, coverage.disposition=COVERED и full_range_acceptance=true для данного короткого текста. Проверить validate: exit 0, ok:true, warnings, violations и swappedNumbers пустые для точной копии. Сверить хэши до и после. Версия CLI может быть 0.0.0 без метаданных дистрибутива; записать фактическую версию, версию pyproject 2.10.1 и commit отдельно. Не объявлять `CLI_INSTALL_PASS`. Статус `SOURCE_RUN_PASS` допустим лишь при реальных успехах. Не объявлять научную приёмку. Выдать JSON и первичные журналы, включая версии, хэши и точные команды. Проверку редактуры оставить на следующий этап.

## 3. Доказательства файлового помощника и завершение
До и после прогона сверить исходный архив и исходники, lockfile, оригинал и пять установленных файлов навыка. Убедиться, что `aiw_ru.__file__` находится в переданном src/, а все 10 зависимостей — в новой venv; проверить отсутствие system-site-packages. Зафиксировать версии через importlib.metadata. Для sha256 сравнить результат с независимым sha256sum.

Создать отдельную спецификацию `[{"id":"P1","exact":"48 пациентов"}]`, выполнить `checks.py bind --source "$ORIGINAL" --spec "$SPEC"` и сохранить реальный JSON реестра. Проверить `ok=true`, `frozen=true`, затем `checks.py protect --source "$ORIGINAL" --candidate "$COPY" --registry "$REGISTRY"` — status PASS. Создать отдельный контрольный файл, заменив только 48 пациентов на 49 пациентов; на нём `protect` обязан вернуть FAIL (исходник не менять). `checks.py read-back --file "$ORIGINAL" --sha256 "$ORIGINAL_SHA"` должен подтвердить matches=true. Вызовы helper могут вернуть exit 0 при содержательном FAIL/BLOCKED: проверять поля JSON, а не только код выхода. Это механическая проверка, не научное разрешение изменения числа.

Сохранить отдельные журналы каждого реального вызова, включая stderr, код выхода, argv, cwd и безопасные env overrides. Не записывать секреты. Возвращать `WORK_SOURCE_RUN_PASS` только после выполнения всех требуемых проверок в Work с десятью точными зависимостями; иначе `BLOCKED`/`FAIL`/`NOT_RUN` по факту. `CLI_INSTALL` и `LOCKED_PROJECT_RUN` остаются NOT_RUN, научная приёмка PENDING. Если данные среды не сохраняются между сессиями, переданный ZIP — повторяемый способ запуска, не доказательство постоянной установки. Не выполнять редактуру диссертации.
