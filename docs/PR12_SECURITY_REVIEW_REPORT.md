# PR #12: исправления security review

Ветка: `feature/v2.5-storage-location-foundation`.
Коммит исправлений: `efe96bd94e532b2b716af3495b0a87a23481bba7` (включает `8bf3e44` и `53383ef`).
Существующий PR: https://github.com/seo79-sec/password-saver/pull/12

## P0 — legacy-папка с EXE

Инвентаризация разделена на legacy и managed. Legacy проверяет только известные
vault-файлы; EXE, checksum и другие пользовательские файлы не читает, не меняет и
не копирует. AppData/staging сохраняют строгий allowlist. Проверки абсолютного
пути, размеров, обычного типа файла, symlink/reparse points не ослаблены.

## P1 — совместимость со старым рабочим каталогом

Добавлен нативный выбор папки Wails без аргумента пути из JavaScript. Backend
выдаёт краткоживущий capability только для выбранной папки. Строгая проверка
селектора, аутентификация паролем/TOTP и отдельный токен подтверждения копирования
используют существующую схему миграции. Назначение фиксировано в AppData;
непустой target и конкурирующие legacy-наборы блокируют перенос.

CWD автоматически не выбирается. В UI есть подсказка для старой рабочей папки и
явное подтверждение создания отдельного пустого vault. Backend блокирует
создание во время выбора/подготовки переноса. Logout, отмена, истечение токена и
запоздалый ответ диалога не возвращают разрешение или чувствительное состояние.

## P2 — стоимость определения расположения

Обычные route/status/save-проверки используют файловые метаданные; активный
контейнер не перечитывается ради вычисления каталога. Полная ограниченная
инвентаризация остаётся для аутентификации и побайтовой сверки копирования.

Консервативное исключение: при наличии AppData, legacy рядом с EXE и квитанции
сохраняется полная сверка хешей legacy. Без неё подмена с теми же размером/mtime
могла бы остаться незаметной. Кэша доверия по этим метаданным нет. Если квитанции
нет, возвращается конфликт без чтения payload. Содержимое активного target
при проверке квитанции не читается.

## Дополнительный аудит

Исправлено пустое поле флагов ACE в Windows SDDL для файлов (`A;;FA`); добавлен
Windows runtime-тест ACL. Он сравнивает значения SID через Windows API,
права доступа и флаги наследования; текстовые алиасы SDDL (`LA` на CI worker)
не влияют на результат. Квитанция читается с ограничением размера и сверкой
идентичности открытого файла. Подтверждение переноса также блокируется при сессии
восстановления. Проверены существующие пути v1/v2, backup, selector, TOTP и
атомарная публикация; production-вызовов `vaultPaths(".")`/`os.Chdir` нет.

## Файлы

- `storage_location.go`, `storage_inventory.go`, `storage_migration.go`,
  `storage_selection.go`: режимы инвентаризации, маршрут, ручной выбор/перенос.
- `app.go`, `v2_setup.go`: жизненный цикл выбора и запрет параллельного создания.
- `storage_permissions_windows.go`: корректный Windows SDDL.
- `storage_migration_test.go`, `storage_review_test.go`,
  `storage_permissions_windows_test.go`, `storage_selection_windows_test.go`:
  регрессии и Windows runtime-проверки.
- `frontend/src/App.svelte`, `frontend/src/security.js`,
  `frontend/src/security.test.js`: ручной выбор и защита поздних ответов.
- `frontend/wailsjs/go/main/App.js`, `frontend/wailsjs/go/main/App.d.ts`,
  `frontend/wailsjs/go/models.ts`: Wails bindings.
- `.github/workflows/ci.yml`: Go tests на Windows перед Wails build и annotations
  с причинами падения отдельных тестов.
- `docs/V2_5_STORAGE_ARCHITECTURE.md`,
  `docs/WINDOWS_STORAGE_MIGRATION_TEST_PLAN.md`: архитектура и ручная проверка EXE.
- `docs/PR12_SECURITY_REVIEW_REPORT.md`: этот отчёт для повторного review.

## Новые проверки

EXE без vault; EXE с checksum; v1/v2 с EXE и посторонними файлами; повреждённый
vault; пустой legacy; отсутствие копирования посторонних файлов; symlink,
необычный тип, oversized selector, неожиданный файл managed-root; ручной выбор
отдельного CWD/Start in; Windows-путь с другой буквой диска; неверный пароль/TOTP;
отмена, истечение, перезапуск; отказ при конфликте; поздний ответ диалога после
Logout; session waiting TOTP; отсутствие лишних payload reads; обнаружение
подмены с теми же размером/mtime; изменение source во время staging и target
после подготовки; ошибки синхронизации до/после публикации. Все данные синтетические.

## Локальные результаты

Go `1.26.4`:

- `go test ./...` — PASS (корневой пакет 48.704 s).
- `go test -race ./...` — PASS (корневой пакет 228.749 s).
- Дополнительный race-прогон ручного выбора с уже созданным пустым scaffold — PASS.
- `go vet ./...`, `go build ./...` — PASS.
- Windows/amd64 `go build ./...` и компиляция Go test binary — PASS.
- `npm test` — PASS, 14 тестов.
- `npm run build` — PASS; сохранены прежние предупреждения Svelte a11y/CSS.
- `git diff --check` — PASS.

## GitHub Actions

Коммит `efe96bd`:

- Windows Go tests, frontend tests/build и Windows Wails build — PASS в обоих запусках.
- Linux go-quality (Go tests, race detector, vet, build) — PASS в обоих запусках.

Запуски:
https://github.com/seo79-sec/password-saver/actions/runs/43976413490
https://github.com/seo79-sec/password-saver/actions/runs/43976423546

Проверено через публичную страницу GitHub Checks. Последующее добавление
этого отчёта не изменяет проверенный код; статус последнего commit доступен
по ссылке ниже.

Актуальный статус PR: https://github.com/seo79-sec/password-saver/pull/12/checks

Первый Windows-прогон новых Go-тестов выявил неточное строковое сравнение SID
в тесте: Windows сериализовал SID пользователя как `LA`. Рабочая реализация ACL
успешно применила DACL. Тест исправлен на проверку SID/ACE средствами Windows;
проверка не ослаблена. CI annotations теперь сохраняют причины падения отдельных
тестов в публичной сводке PR.

## Ограничения и ручная проверка

Настоящий Windows GUI в облачной Linux-среде не запускался. План:
https://github.com/seo79-sec/password-saver/blob/feature/v2.5-storage-location-foundation/docs/WINDOWS_STORAGE_MIGRATION_TEST_PLAN.md

Перед одобрением проверить EXE с checksum, реальный ярлык с другим Start in,
другой физический диск, нативный диалог, TOTP, backup/recovery, ACL, отказы диска
и повторный запуск после прерывания. Windows-тест другой буквы использует
временное сопоставление синтетического каталога и не заменяет физический диск.

Остаются ограничения write-through/fsync на Windows, межпроцессные файловые
гонки с процессом того же пользователя, откат при полном контроле ФС и
дополнительное чтение legacy при проверке квитанции. Посторонние legacy-файлы и
диагностические архивы не копируются, но сохраняются у источника. Рабочая папка
не сканируется вслепую; её требуется явно выбрать.

Криптографические форматы, AES-256-GCM, Argon2id и релиз v2.0.0 не изменены.
Реальные пользовательские хранилища не использовались.

Публикация комментария/редактирование описания через GitHub API в текущем
окружении недоступны (`Forbidden`). Поэтому полный отчёт включён в файлы этого
PR; его можно перенести в комментарий без изменения содержания. Merge не выполнялся;
требуется повторный security review.
