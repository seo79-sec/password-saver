# Подготовка выпуска PasswordSaver Standard 2.5.0 для Windows

## Кандидат из проверенного коммита

CI собирает Windows x64 ZIP из SHA, указанного в запуске, и публикует его на
14 дней в **Actions → CI → Run summary → Artifacts**. Для повторной сборки
доступен **Actions → Build Windows release candidate → Run workflow** с
выбором `main`. Оба пути выполняют один workflow. В нём есть Linux-тесты Go
и race detector, vet, frontend-тесты, Playwright, Windows-тесты Go, сборка
Wails и запуск EXE в изолированном профиле. Запуск процесса подтверждает
старт. Приёмка окна Wails/WebView2 и системных диалогов записывается отдельно.

Для выпуска используйте прогон на точном проверенном коммите **после merge**
в `main`. Проверьте SHA и строку `Source: refs/heads/main` в README внутри
ZIP. Кандидаты из веток и PR подходят для проверки изменений.
Кандидат из `main` берётся из его собственного успешного прогона.

## Скачать и проверить

1. Войдите в GitHub и скачайте артефакт
   `PasswordSaver-Standard-2.5.0-Windows-x64`.
2. Распакуйте внешнюю загрузку Actions. В ней находятся
   `PasswordSaver-Standard-2.5.0-Windows-x64.zip` и одноимённый
   файл с окончанием `.zip.sha256`.
3. Сверьте ZIP и извлечённый EXE. Независимый Linux job в CI скачивает
   опубликованный артефакт, проверяет оба SHA-256 по результату Windows
   сборки и сверяет точный список файлов. Оба хеша есть в Summary прогона
   и в аннотации задания проверки.

   ```powershell
   $archive = 'PasswordSaver-Standard-2.5.0-Windows-x64.zip'
   $zipHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
   if ((Get-Content -LiteralPath ($archive + '.sha256') -Raw).TrimEnd() -cne "$zipHash  $archive") {
     throw 'ZIP SHA-256 mismatch'
   }
   $output = Join-Path ([IO.Path]::GetTempPath()) ('passwordsaver-verify-' + [Guid]::NewGuid())
   Expand-Archive -LiteralPath $archive -DestinationPath $output
   $exe = Join-Path $output 'PasswordSaver/password-saver.exe'
   $exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
   $manifest = Join-Path $output 'PasswordSaver/SHA256SUMS.txt'
   if ((Get-Content -LiteralPath $manifest -Raw).TrimEnd() -cne "$exeHash  password-saver.exe") {
     throw 'EXE SHA-256 mismatch'
   }
   ```

Внутри ZIP допустимы ровно `PasswordSaver/password-saver.exe`,
`PasswordSaver/README.txt` и `PasswordSaver/SHA256SUMS.txt`. Хранилища,
ключи восстановления, тестовые данные, резервные и диагностические
копии остаются вне архива. Для запуска распакованного EXE требуется
Microsoft Edge WebView2 Runtime.

## Финальное решение и публикация

1. Сверьте зелёный CI и хеши с коммитом `main`. Пройдите и зафиксируйте
   [план приёмки Windows](WINDOWS_MANUAL_TEST.md) на этом же EXE. Просмотрите
   [описание выпуска](RELEASE_NOTES_V2.5.0.md) и [изменения](../CHANGELOG.md).
2. После отдельного решения о выпуске создайте тег `v2.5.0` именно на
   проверенном SHA `main`. На странице **GitHub Releases → Draft a new release**
   выберите этот тег и приложите проверенные ZIP и `.zip.sha256` из того же
   прогона. Вставьте release notes. Сверьте SHA-256 после скачивания из черновика
   и опубликуйте его после финального подтверждения.
3. Существующие тег и релиз `v2.0.0` сохраняются. Workflow и заметки версии
   2.0.0 относятся к прежнему выпуску.

Сборка кандидата работает с правами чтения и создаёт только Actions artifact.
Подготовка версии 2.5.0 не создаёт тег или GitHub Release.
