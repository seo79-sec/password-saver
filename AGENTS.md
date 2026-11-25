# AGENTS.md

## Контекст проекта
- Перед началом любой задачи прочитай `docs/SPEC.md` и `docs/PROGRESS.md`.
- Не сканируй весь репозиторий без необходимости: работай только с файлами и пакетами, указанными в задаче.

## Команды проверки
- Go тесты с детектором гонок: `go test -race ./...`
- Frontend (в каталоге `frontend`, в порядке запуска в CI): `npm ci`, `npm run build`, `npm test`.
- Playwright (в каталоге `frontend`, после сборки): `npx playwright install --with-deps chromium`, затем `npm run test:ui`.
- Go (из корня, после сборки frontend): `go test ./...`, `go vet ./...`, `go build ./...`. Тесты с детектором гонок также запускай после сборки frontend.
- Сборка приложения на Windows x64 (из корня): `go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0`, затем `wails build -platform windows/amd64`.

## Правила безопасности и архитектуры
1. **Криптография (`crypto/v2/`, `crypto/`, `internal/replicastore`):** не меняй алгоритмы, параметры KDF/HKDF, размеры nonce/солей, структуру AAD и форматы контейнеров без явного указания в задаче.
2. **Изоляция 3.0:** не подключай `internal/syncmerge` и `internal/replicastore` к рабочему vault или Wails, если это прямо не указано в задаче.
3. **Завершение задачи:** в конце работы обязательно обнови `docs/PROGRESS.md` (актуализируй таблицу состояний и раздел «Далее» под выполненную задачу, сохраняя компактный формат).
