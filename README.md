# fp-rdap

RDAP-клиент для Free Pascal / Lazarus: запросы к реестрам доменов и IP-адресов по протоколу
RDAP ([RFC 9082]/[RFC 9083]) с роутингом через официальные IANA bootstrap-файлы
([RFC 8524], [RFC 9224], [RFC 9225]).

## Возможности

- Запросы: `domain`, `ip`, `autnum`, `entity`.
- Автоматический выбор RDAP-сервера по домену (multi-label TLD, `co.uk`) или IP
  (longest-prefix-wins) из bootstrap-файлов IANA; bootstrap-файлы грузятся с диска или из строки.
- Статусы результата: `rqsOK`, `rqsNotFound`, `rqsRateLimited`, `rqsError` + разбор
  RDAP error-объекта (`errorCode`/`title`) и заголовка `Retry-After`.
- Таймауты соединения/IO, User-Agent, редиректы.
- Встроенный мок (`TRDAPClientMock`) для тестов без сети.

## Структура

| Путь | Назначение |
|------|------------|
| `src/rdapclient.pas` | Вся библиотека: клиент, bootstrap, чистые хелперы (IP/CIDR/домены) |
| `rdap_rt.lpk` | Lazarus-пакет (runtime-only) |
| `tests/` | FPCUnit-тесты: консольный и GUI-раннер |
| `demo/` | Консольное демо |

## Установка

Установите пакет `rdap_rt.lpk` в Lazarus (Package → Open → Install) или просто добавьте
`src/rdapclient.pas` в проект. Требуется FPC 3.2+, FCL (fpjson, fphttpclient) и OpenSSL
библиотеки в PATH для HTTPS.

## Быстрый старт

```pascal
uses rdapclient;

var
  B: TRDAPBootstrap;
  C: TRDAPClient;
begin
  // Файлы с https://data.iana.org/rdap/ положите рядом с программой
  B := TRDAPBootstrap.Create;
  try
    B.LoadFromLocalFiles('dns.json', 'ipv4.json', 'ipv6.json');
    // Либо из строки: B.LoadDNSFromString(EmbeddedDNSSnapshot);

    C := TRDAPClient.Create;
    try
      C.Bootstrap := B;                       // bootstrap не принадлежит клиенту
      C.QueryDomain('example.com');
      case C.LastStatus of
        rqsOK:          Writeln(C.GetObjectTitle, ' | ', C.GetObjectType);
        rqsNotFound:    Writeln('Not found');
        rqsRateLimited: Writeln('Rate limited, retry after ', C.RetryAfter, 's');
      end;
    finally
      C.Free;
    end;
  finally
    B.Free;
  end;
end;
```

Без bootstrap задайте `C.BaseURL := 'https://rdap.org/'` — но тогда `QueryAutNum`/`QueryEntity`
также потребуют явного `BaseURL` (bootstrap их не покрывает).

Для тестов своего кода используйте `TRDAPClientMock`: `SetupMock(json, code)`,
`SetupMock(json, code, ['Retry-After: 120'])` (с заголовками ответа),
`SetupMockError(msg)`, история URL — `MockRequestURL(i)`.

## Тесты

```bash
C:\lazarus\lazbuild.exe tests\rdap_tests.lpi
tests\rdap_tests.exe --all --format=plain
```

Юнит-тесты не ходят в сеть — сетевой слой подменяется моком.

## Демо

`demo/rdap_demo.lpi` — положите рядом с exe файлы `dns.json`, `ipv4.json`, `ipv6.json`
с https://data.iana.org/rdap/ ; без них демо уходит через `https://rdap.org/`.

## Ограничения

- Клиент не потокобезопасен: один экземпляр на поток.
- Домены в запросах — A-label (punycode); U-label (например, `пример.рф`) не конвертируются.
- Ответ HTTP-сервера не ограничен по размеру.

## Лицензия

MIT — см. [LICENSE](LICENSE).

## Изменения

### 2026-11-13 — Надёжность bootstrap (этап 4 дорожной карты)

- Все методы загрузки bootstrap (`LoadDNS`/`LoadIPv4`/`LoadIPv6`/`Load*FromString`)
  работают по схеме «разбор → подмена»: неудачная перезагрузка (битый или
  отсутствующий файл, JSON без `services`) больше не оставляет bootstrap пустым —
  ранее загруженные данные продолжают работать. Раньше поля очищались до разбора.
- Выбор base URL из записи bootstrap валидируется строго: URL-часть записи обязана
  быть массивом строк (допустима и одна строка), все элементы — строки, URL не пуст.
  Нарушение → `ERDAPError` с номером записи («Service N»); «чужие» исключения
  fpjson (`EConvertError`/`EJSONError`) наружу больше не выходят.
- Новые методы `LoadIPv4FromString`/`LoadIPv6FromString` — симметрично
  `LoadDNSFromString`.

### 2026-11-13 — Коды ошибок RFC 9083 (этап 3 дорожной карты)

- **Ломающее изменение:** HTTP 400/401/403/503 больше не бросают исключение —
  как 404/429, они приходят как статус `rqsError`. Тело ответа (RFC 9083 §6.2
  error-объект) разбирается в `LastErrorCode`/`LastErrorTitle`/`LastJSON`,
  сырой текст остаётся в `LastRawJSON`; если тело не JSON, статус всё равно
  `rqsError`, а `LastErrorCode` = 0. Раньше эти коды приводили к `ERDAPError`
  («Unexpected response status code»).
- Ответы с кодами вне списка `[200, 400, 401, 403, 404, 429, 503]` (например,
  500) по-прежнему приводят к исключению `ERDAPError`.

### 2026-11-13 — Заголовки ответа и Retry-After (этап 2 дорожной карты)

- Заголовки последнего ответа — часть общего механизма клиента: снапшот хранится
  в защищённом поле `TRDAPClient` (очищается перед каждым запросом), доступ через
  protected virtual `GetResponseHeader`. Разбор `Retry-After` перенесён из
  `DoHTTPGetJSON` в `ProcessLastResponse` — единый путь для реального клиента и мока.
- `RetryAfter` теперь понимает обе формы RFC 7231: число секунд и HTTP-date
  (дата в прошлом → 0, нечитаемое значение → 0). Раньше распознавалась только
  форма «число секунд». Новый чистый хелпер — `TryParseRetryAfter`.
- Мок может задавать заголовки ответа: `SetupMock(json, code, ['Retry-After: 120'])`.
- Наблюдаемое поведение почти не изменилось: `RetryAfter` теперь ненулевой для
  date-формы заголовка и обнуляется, если ответ не дошёл до разбора
  (например, 200 с битым JSON).

### 2026-11-13 — UTF-8 корректность (этап 1 дорожной карты)

- Все строки библиотеки — UTF-8 по контракту. Модуль `rdapclient` в секции
  `initialization` выставляет `DefaultSystemCodePage := CP_UTF8` на весь процесс:
  без этого fcl-json из FPC 3.2.2 на Windows с не-UTF-8 системной кодировкой
  портит `\uXXXX`-эскейпы и литеральные не-ASCII байты при разборе ответов
  при любом значении флага `GetJSON`. Подключение модуля переопределяет
  кодипейдж по умолчанию у хост-приложения — учитывайте это, если приложение
  полагается на системную ANSI-кодировку.
- Bootstrap-файлы читаются явно как UTF-8 (`LoadFromFile(..., TEncoding.UTF8)`):
  раньше `TStrings` декодировал их системной ANSI-кодировкой.
- `ParseJSONSafe`/`TryParseJSON` используют `GetJSON(..., True)`.

[RFC 9082]: https://www.rfc-editor.org/rfc/rfc9082
[RFC 9083]: https://www.rfc-editor.org/rfc/rfc9083
[RFC 8524]: https://www.rfc-editor.org/rfc/rfc8524
[RFC 9224]: https://www.rfc-editor.org/rfc/rfc9224
[RFC 9225]: https://www.rfc-editor.org/rfc/rfc9225
