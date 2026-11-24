# Приёмка упаковки R2 Autonomous

Итог сборщика: **AUTONOMOUS_PACKAGE_CANDIDATE**. Установка в ChatGPT Work: **WORK_AUTONOMOUS_PENDING**. Научная приёмка: **SCIENTIFIC_ACCEPTANCE_PENDING**.

Это холодные запуски собранного ZIP на Linux x86_64, CPython 3.12.3, glibc 2.39, uv 0.13.9 (x86_64-unknown-linux-gnu). Целевой Work ранее был на CPython 3.12.14 и glibc 2.41. Результат сборщика на него не переносится.

Предыдущий отчёт `WORK_SOURCE_RUN_PASS` относится к отдельному runtime и здесь не используется как новый запуск.

## Пакет

- Файл: `russian-medical-academic-editor-R2-autonomous.zip`
- Размер: 5533530 байт
- SHA-256: `60f493286fbde8e5f759bd8339f137f57fafa9a1ba56e5dfa709bbd456de1485`
- Встроенный runtime: `f0d0bfba47026ea033ffdffdf76d4a4fe10946ec955ac616d4731e6d28693bf4`, 5479858 байт, git blob `de5852884460187f467c5685d0bda81bd4ee78bb`
- Исходный коммит навыка: `fef168622d9ffa1d7f8f9ebb241b6932659d62aa`
- Коммит публикации runtime: `87712f56edcfee5e1f8d30729f6c77d894f0a859`

Корень архива один: `russian-medical-academic-editor/`. Пять научных файлов совпали с R2 побайтно. Менялись только инструкции подключения. `checks.py`, исходники CLI, lockfile и версии зависимостей не менялись. Commit, push и merge не выполнялись.

## Матрица

| ID | Статус | Доказательство |
|---|---|---|
| P01 | PASS | `sha256sum -c` handoff, baseline ZIP 7/7, source 45/45 |
| P02 | PASS | размер 5479858, SHA-256 и git blob runtime, `verify_runtime.py`, 10 wheel |
| P03 | PASS | в git diff только два документа инструкций; frozen-файлы, src, lockfile, pyproject и prek без изменений |
| P04 | PASS | SKILL.md и runtime-and-artifacts.md задают один порядок: bootstrap, затем абсолютный source-run |
| P05 | PASS | один корень, CRC чистый, встроенный ZIP совпал побайтно |
| P06 | PASS | распаковка A вне репозитория, офлайн-установка 10/10, provenance из новой venv |
| P07 | PASS | scan/validate, coverage COVERED, bind, protect 48 PASS и 48→49 FAIL, read-back |
| P08 | PASS | независимая распаковка B, другой `work_dir`, venv A перед этим переименована |
| P09 | PASS | другой cwd, чужой PYTHONPATH, поддельный `aiw-ru` в PATH не исполнялся |
| P10 | PASS | отсутствие, порча и подмена архива останавливаются до установки; небезопасный ZIP отвергается проверкой структуры |
| P11 | PASS | нет uv и срыв install дают BLOCKED/FAIL без RUNTIME_READY; сетевого fallback в командах нет. Процесс на другом Python: NOT_RUN, второго интерпретатора на сборщике нет |
| P12 | PASS | живые поля JSON проверены; функция `smoke_problems` отвергает нулевые слова, classifier, warning и не-COVERED |
| P13 | PASS | хэши архива, исходников и lockfile после прогонов прежние; научный статус PENDING |
| P14 | PASS | целевые тесты 206 passed; полная locked suite: 1537 passed, 44 skipped, 1 xfailed; ruff и ty без замечаний |
| P15 | PASS | ZIP, отчёт и журналы лежат в каталоге артефактов, SHA256SUMS сверен |
| W01–W05 | NOT_RUN | автономный ZIP в Work ещё не устанавливался |
| E01 | PENDING | научный пилот не начат |

## Сессии сборщика

- A: `/tmp/rmae-r2-autonomous-u5q57a8u`, cwd `/tmp/rmae-cold-a-9lht2tzx/cwd`
- B: `/tmp/rmae-r2-autonomous-8hrdjuyu`, cwd `/tmp/rmae-cold-b-12gczgts/cwd`
- Обе: `aiw-ru 0.0.0`, заявленная версия проекта 2.10.1, `CLI_INSTALL=NOT_RUN`, `LOCKED_PROJECT_RUN=NOT_RUN`, `scientific_acceptance=PENDING`
- Проба: 11 слов, `contextMode=academic`, validate `ok=true`, coverage `COVERED`, protect положительной копии `PASS`, замена 48 на 49 `FAIL`

Сборка и эти два запуска не являются эксплуатацией установленного навыка в Work.

Перед публикацией в ветку `bootstrap.py` приведён к длине строки репозитория. Повторный холодный запуск опубликованного ZIP дал `RUNTIME_READY`. Полная матрица в журналах сделана на предыдущей сборке с тем же runtime; отличие только в переносах строк помощника.
