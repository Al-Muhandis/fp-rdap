# Changelog

Журнал релизов fp-rdap. Версия релиза — четыре компонента
`Major.Minor.Release.Build`, как её показывает OPM (Lazarus Online Package
Manager); тег релиза — `v<версия>`. Запись добавляется на каждый релиз;
изменения наблюдаемого поведения в процессе разработки фиксируются в README,
раздел «Изменения».

## 1.0.0.0 — 2026-11-14

Первый публичный релиз: RDAP-клиент для Free Pascal / Lazarus.

### Добавлено

- Запросы `domain`, `ip`, `autnum`, `entity` (RFC 9082/9083).
- Роутинг через bootstrap-файлы IANA (RFC 8524/9224/9225): загрузка с диска
  или из строки, longest-prefix для IP, multi-label TLD для доменов;
  перезагрузка отказоустойчива (parse-then-swap), записи `services`
  валидируются при выборке.
- IDNA: U-label домены конвертируются в A-label — punycode (RFC 3492) плюс
  прагматичное IDNA-маппирование fp-idn (приведение регистра ASCII/кириллицы/
  греческого, разделители label, отклонение недопустимых имён с `ERDAPError`)
  через пакет `fpidn_rt` ≥ 1.1
  ([fp-idn](https://github.com/al-muhandis/fp-idn)).
- Статусы результата `rqsOK`/`rqsNotFound`/`rqsRateLimited`/`rqsError`;
  разбор RFC 9083 error-объекта и заголовка `Retry-After` (секунды и
  HTTP-date).
- `MaxResponseSize` — лимит размера ответа (по умолчанию 10 МБ) с обрывом
  скачивания; таймауты соединения/IO, User-Agent, редиректы.
- `TRDAPClientMock` для тестов без сети: тело/код/заголовки ответа, история
  URL.
- Все строки библиотеки — UTF-8 по контракту; разбор JSON не зависит от
  кодипейджа процесса.

### Требования

FPC 3.2+, FCL (fpjson, fphttpclient), пакет `fpidn_rt`, OpenSSL-библиотеки
в PATH для HTTPS.
