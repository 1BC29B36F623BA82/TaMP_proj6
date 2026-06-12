# Тестирование — TaMP_proj6

## Стратегия (кратко)
Трёхуровневое тестирование:
- **Unit** — логика модулей `rsa`, `sha1`, `steganography`, `wav_handler` через **Qt Test** (`test/functionality/`).
- **Integration** — сетевой протокол сервера (команды `SHA1 / RSA / deRSA / NEWTON / STEG / HELP`) через TCP-клиент.
- **System / UI** — ручная проверка GUI-клиента (Connect/Disconnect/Send).

## Артефакты
Все тестовые таблицы собраны в `TaMP_proj6_Testing.xlsx` в формате учебного шаблона — 6 листов:
Тест-план, Чек-лист + Дефекты, Тест-кейс 1 (STEG), Тест-кейс 2 (RSA), Дефект, Отчет.

Файл xlsx и PNG-диаграммы воспроизводятся скриптами из `tools/` (см. tools/README.md).

## Запуск unit-тестов
```bash
mkdir -p build/test && cd build/test
qmake6 ../../test/functionality/tests.pro && make
QT_QPA_PLATFORM=offscreen ./tst_functionality
```
Результат: **19 passed, 0 failed**.

## Эталонные данные
- SHA-1: векторы FIPS PUB 180-1 (`""`, `abc`, `hello`, pangram).
- RSA: `p=61, q=53` -> `n=3233, e=17, d=2753`.
- WAV: сгенерированные PCM / 16 бит / моно.
