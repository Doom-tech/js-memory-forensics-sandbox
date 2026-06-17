# Руководство пользователя

Это короткая инструкция, чтобы не вспоминать каждый раз команды сборки и запуска.

## Для чего это нужно

Программа помогает посмотреть, какие строки появляются в памяти после выполнения
обфусцированного JavaScript. Например, если ссылка или команда собирается через
`String.fromCharCode`, `atob` или конкатенацию, её может не быть в исходном файле,
но она появится во время работы скрипта.

## Сборка

Если на Linux CMake ругается `No CMAKE_CXX_COMPILER`, значит сначала нужно
поставить компилятор и базовые инструменты сборки:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential cmake doxygen git pkg-config
```

В проекте для этого есть готовый скрипт:

```bash
bash scripts/install_ubuntu_deps.sh
```

На macOS зависимости можно поставить через Homebrew:

```bash
brew install v8 doxygen
```

Дальше обычная сборка:

```bash
cmake -S . -B build -DJSFS_REQUIRE_V8=ON
cmake --build build
```

Во время сборки автоматически генерируется HTML-документация:

```text
docs/api/html/index.html
```

## Тесты

```bash
ctest --test-dir build --output-on-failure
```

Тестов сейчас 10. Они проверяют не V8 как библиотеку, а мою core-логику:
base64, парсер maps, фильтр подозрительных строк, извлечение строк и поиск
значений, отмеченных через `mark`.

## Пример запуска

Вариант, который работает и на macOS, потому что не трогает `/proc/self/maps`:

```bash
./build/js-memory-sandbox \
  --out=analysis_out \
  --no-memory-dump \
  samples/harmless_obfuscated.js
```

Полный запуск с дампом памяти нужен на Linux:

```bash
./build/js-memory-sandbox \
  --out=analysis_out \
  --timeout-ms=2000 \
  --max-old-space-mb=64 \
  --max-region-mb=128 \
  --skip-file-backed \
  samples/harmless_obfuscated.js
```

## Полезные параметры

```bash
./build/js-memory-sandbox --help
```

Самые важные опции:

- `--out=DIR` — куда складывать результат;
- `--timeout-ms=N` — лимит времени для JS;
- `--max-old-space-mb=N` — лимит V8 heap;
- `--maps=PATH` — свой maps-файл в формате `/proc/self/maps`;
- `--skip-file-backed` — не дампить обычные file-backed регионы;
- `--no-memory-dump` — не делать raw memory dump;
- `--no-heap-snapshot` — не писать V8 heap snapshot.

## Что смотреть после запуска

В папке результата обычно лежит:

- `report.md` — короткий итог;
- `strings.tsv` — все найденные строки;
- `hits.tsv` — подозрительные строки;
- `tracked_locations.tsv` — где нашлись значения из `mark`;
- `heap_snapshot.json` — снимок V8 heap;
- `memory/` — raw dump регионов памяти, если запуск был на Linux.

## Как пометить значение в JS

Внутри анализируемого скрипта можно вызвать:

```js
mark("payload", payload);
```

После этого программа постарается найти байты `payload` в дампах памяти и
запишет совпадения в `tracked_locations.tsv`.
