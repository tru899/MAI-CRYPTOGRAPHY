# DES / DEAL

Все команды — из этой папки:

```bash
cd /Users/user/Desktop/vscode/MAI/labs_5_sem/crypto
```

| папка | что это |
|---|---|
| `DES/` | алгос |
| `DES.Tests/` | автотесты |
| `DES.Demo/` | демо |
| `DES.Demo/files/` | сюда класть свои файлы для шифрования |
| `DES.Demo/out/` | сюда пишутся `.enc` (зашифрованный) и расшифрованная копия с тем же расширением |

## Сборка

```bash
dotnet build DES.Demo
dotnet build DES.Tests
```

## Тесты

```bash
dotnet test DES.Tests
```

Только часть тестов — по имени:

```bash
dotnet test DES.Tests --filter "FullyQualifiedName~Zeros"
dotnet test DES.Tests --filter "FullyQualifiedName~DesTests"
dotnet test DES.Tests --filter "FullyQualifiedName~Validation"
```

## Демо

Всё сразу — случайные данные и все файлы из `DES.Demo/files`, все режимы, набивка PKCS7:

```bash
dotnet run -c Release --project DES.Demo
```

Параметры (пишутся после `--`):

| параметр | значения | по умолчанию |
|---|---|---|
| `--cipher` | `DES`, `DEAL-128`, `DEAL-192`, `DEAL-256`, `all` | DES и DEAL-128 |
| `--mode` | `ECB`, `CBC`, `PCBC`, `CFB`, `OFB`, `CTR`, `RD`, `all` | `all` |
| `--padding` | `ZEROS`, `ANSIX923`, `PKCS7`, `ISO10126`, `all` | `PKCS7` |
| `--text "…"` | зашифровать свой текст | — |
| `--hex A1B2…` | зашифровать свои байты | — |
| путь к файлу или папке | зашифровать их | — |
| `--key HEX` | свой ключ: DES — 16 hex-символов, DEAL — 32/48/64 | тестовый |
| `--iv HEX` | свой IV, длина блока: DES — 16 hex, DEAL — 32 | случайный |
| `--delta N` | шаг для RD, нечётный | 12345 |

Если указаны `--text`, `--hex` или пути — шифруются только они.

Примеры:

```bash
dotnet run -c Release --project DES.Demo -- --cipher DES --mode CBC --padding PKCS7 --text "Привет"
dotnet run -c Release --project DES.Demo -- --cipher DES --mode ECB --padding all --hex 00
dotnet run -c Release --project DES.Demo -- --cipher all --mode all --padding all --text " "
dotnet run -c Release --project DES.Demo -- --cipher DEAL-128 --mode CTR DES.Demo/files/pic.jpg
dotnet run -c Release --project DES.Demo -- --mode CFB --padding ANSIX923 DES.Demo/files
dotnet run -c Release --project DES.Demo -- --cipher DES --mode ECB --padding ZEROS --key 133457799BBCDFF1 --hex 0123456789ABCDEF
```

Последняя команда — эталон из стандарта, должно получиться `85E813540F0AB405`.

Набивка влияет только на ECB, CBC и PCBC. CFB, OFB, CTR и RD работают с данными любой длины, набивку не используют.
