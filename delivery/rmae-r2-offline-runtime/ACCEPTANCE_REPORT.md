# Итог приёмки автономной среды RMAE R2

Повторная сверка перед публикацией в ветку `build/rmae-r2-offline-runtime`, 24 ноября 2026, 16:30 по Москве. Комплект собран из коммита `fef168622d9ffa1d7f8f9ebb241b6932659d62aa`, версия проекта 2.10.1. Исходный код CLI, навык, `uv.lock` и версии зависимостей в этом коммите публикации не правились.

## Статусы

| Область | Статус |
|---|---|
| Автономный архив | `OFFLINE_BUNDLE_READY` |
| Source-run на сборщике | `BUILDER_SOURCE_RUN_PASS` |
| Эксплуатация в ChatGPT Work | `NOT_RUN` |
| Установленный CLI | `NOT_RUN` |
| `uv sync --locked` как рабочий запуск | `NOT_RUN` |
| Научный редакторский пилот | `NOT_RUN` |
| Merge в основную ветку | `NOT_RUN` |
| Релиз | `NOT_RUN` |

Сборщик, на котором прошёл source-run: Linux x86_64, CPython 3.12.3, glibc 2.39, uv 0.13.9. Целевая среда Work остаётся CPython 3.12.14, glibc 2.41, uv 0.13.9. Совпадение source-run на сборщике не переносится на Work.

Предыдущее испытание в Work, по приложенному аудиту, остаётся `BLOCKED`: в кэше Work не было десяти wheel, `scan` и `validate` там не запускались. Эта публикация передаёт недостающие wheel и не повторяет сессию Work.

`python -m aiw_ru --version` из каталога `src` напечатал `aiw-ru 0.0.0`. Это запуск из исходников, не установленный дистрибутив.

## Повторная сверка артефактов

Перед копированием в этот каталог заново проверены байты:

| Файл | SHA-256 | Байты |
|---|---|---|
| `RMAE_R2_OFFLINE_RUNTIME.zip` | `f0d0bfba47026ea033ffdffdf76d4a4fe10946ec955ac616d4731e6d28693bf4` | 5479858 |
| `BUILD_REPORT.json` | `02c0f589ef09c721d38ba87dbb25c43215885be50896d27bdd3c28b2f3f62d2a` | 16306 |
| `PRIMARY_BUILD_LOGS.zip` | `1ae2718083fa17834126833ce91c9881141ff494731e10af8f8b029640b49992` | 55619 |

`verify_runtime.py --archive` по этому ZIP снова вернул `OFFLINE_BUNDLE_READY`: 10 wheel, 45 файлов исходников, CRC архива пустой. Сумма десяти wheel — 5079675 байт. Внутренний `RMAE_R2_CLI_RUNTIME_BUNDLE.zip` совпадает с `3718219490c52357e6bf9bb2564cd46dbf9252b7b9844ad6122f2d2393b232bb`.

`WHEEL_MANIFEST.json`, `prepare_offline_bundle.py`, `verify_runtime.py` и `00_READ_FIRST.md` скопированы без замены байтов. Их SHA-256 совпадают с `SHA256SUMS.txt` пакета handoff: `5b0ee982f2c3421fe81b13cdd5eaf72b1f17dec1a46afb47d9c47a153aeabe59`, `96dbde12ee34e54e3d0963bae2fb1612228862fe2dbd48f1a62c01fa309da9f9`, `62bb537155e101f12f2a8be55a0e95ad057729cb3455e50d73f0d8bb1762eb28`, `be6f2f74d7783dc3c54037b575d27aab4ea82d458860c714a64b2c0cb4030512`. Файл `00_READ_FIRST.md` в этом каталоге — та же инструкция, что лежит внутри runtime ZIP и в handoff как `WORK_OFFLINE_READ_FIRST.md`.

Полный перечень контрольных сумм каталога — в соседнем `SHA256SUMS.txt`. SHA этого отчёта туда входит и поэтому в таблицу выше не записан: он зависит от текста файла.

## Критерии B01–B08 и S01–S08

| ID | Статус | Основание |
|---|---|---|
| B01 | PASS | SHA256SUMS handoff и вложенного builder, CRC входных ZIP |
| B02 | PASS | 45/45 файлов: размер, SHA-256 и git blob против `fef1686` |
| B03 | PASS | `verify_runtime.py --inputs`: 10 версий, URL, размеров и хешей из `uv.lock` |
| B04 | PASS | 10 wheel скачаны с `files.pythonhosted.org`, повторный GET совпал по SHA-256 |
| B05 | PASS | WHEEL, METADATA, RECORD, CRC; два cp312 manylinux x86_64 и восемь py3-none-any |
| B06 | PASS | В ZIP ровно инструкция, манифест, суммы, исходный архив и `wheelhouse/` |
| B07 | PASS | До сборки и после неё рабочее дерево было чистым. Публикация добавляет этот каталог, исключение ZIP из лимита 512 КБ в `prek.toml` и исключение каталога поставки из ruff и ty |
| B08 | PASS | ZIP лежит в ветке, SHA-256 после копирования совпал |
| S01 | PASS | Сборщик: Python 3.12.3, Linux x86_64, glibc 2.39, uv 0.13.9. Это не хост Work |
| S02 | PASS | Новая venv без system-site-packages, пустой кэш, установка `--offline` в сетевом пространстве имён |
| S03 | PASS | 10/10 версий `importlib.metadata`, модули из venv, `aiw_ru` из `src` |
| S04 | PASS | scan: код 0, 11 слов, `contextMode=academic`, без classifier; coverage `COVERED` |
| S05 | PASS | validate точной копии: код 0, `ok=true`, пустые warnings, violations, swappedNumbers |
| S06 | PASS | sha256 помощника совпал с `sha256sum`; bind `ok` и `frozen`; копия `PASS`; замена числа `FAIL`; read-back `matches=true` |
| S07 | PASS | Хеши архива, lockfile, пяти файлов навыка и фразы после прогона те же |
| S08 | PASS | Команды, коды выхода, stdout и stderr лежат в `PRIMARY_BUILD_LOGS.zip` |

Помощник в S06 запускался из `runtime/source/skills/russian-medical-academic-editor` внутри архива. Это не проверка установленной копии навыка в Work.

## Что сознательно не делалось

Модели, зависимости dev, train и ML в архив не входили. Hatchling для source-run не требовался. Обхода сетевых ограничений Work не было: wheel получены в среде сборки, где `files.pythonhosted.org` разрешён. Сессия Work этим коммитом не открывается.
