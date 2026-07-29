# Выпуск релиза

Этот runbook описывает выпуск Маяка 0.3.0 и новее с подписанными
update-артефактами. Он не заменяет CI: тег создаётся только после зелёных
проверок `main`.

## Модель доверия

У автообновления и системной подписи разные задачи:

- minisign-подпись Tauri доказывает, что update-пакет выпущен проектом и не
  изменён после сборки;
- Apple notarization и Microsoft Authenticode подтверждают издателя
  операционной системе и уменьшают предупреждения Gatekeeper/SmartScreen.

Пока системных сертификатов нет, первая ручная установка может показывать
предупреждение. Встроенный updater всё равно отклоняет пакет без корректной
minisign-подписи.

Публичный ключ находится в `src-tauri/tauri.conf.json`. Приватный ключ или его
пароль нельзя добавлять в репозиторий, issue, логи CI или release assets.

## Хранение ключа

Release workflow использует два repository secret:

- `TAURI_SIGNING_PRIVATE_KEY`;
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.

Локальный зашифрованный backup владельца находится в
`~/.tauri/mayak-updater.key` с правами `0600`. Пароль хранится в macOS
Keychain с service `app.mayak.network.updater`. Ключ и пароль необходимо
дополнительно сохранить в независимом защищённом backup или password manager:
GitHub не позволяет прочитать secret обратно.

## Подготовка

1. Обновите `CHANGELOG.md`.
2. Синхронизируйте версию в `package.json`, `package-lock.json`,
   `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock` и
   `src-tauri/tauri.conf.json`.
3. Выполните:

   ```bash
   npm ci
   npm run check
   cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
   cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
   cargo test --manifest-path src-tauri/Cargo.toml --all-targets
   ```

4. Убедитесь, что CI `main` зелёный и рабочее дерево чистое.

## Публикация

Создайте и отправьте аннотированный тег, совпадающий с версией приложения:

```bash
git tag -a v0.3.0 -m "Маяк 0.3.0"
git push origin v0.3.0
```

Workflow:

1. сверяет тег со всеми файлами версии;
2. создаёт draft release;
3. последовательно собирает macOS DMG и Windows NSIS/MSI, чтобы jobs не
   перезаписали общий `latest.json`;
4. создаёт и загружает подписанные updater-артефакты;
5. объединяет платформы в `latest.json`;
6. проверяет версию, подписи, HTTPS URL и наличие app/NSIS/MSI targets;
7. создаёт SHA-256 для обычных установщиков;
8. только после успеха публикует release как latest.

При ошибке draft остаётся непубличным и endpoint автообновления продолжает
указывать на предыдущий полный релиз.

## Проверка выпуска

После публикации:

```bash
gh release view v0.3.0
gh release download v0.3.0 --pattern latest.json
node scripts/validate-updater-manifest.mjs latest.json 0.3.0
```

Проверьте ручную установку и обновление на реальном Mac и Windows-компьютере.
Артефакт `latest.json` должен быть доступен через
`https://github.com/alxshmrv/mayak/releases/latest/download/latest.json`.

## Ротация или утрата ключа

Не заменяйте публичный ключ и signing secret одновременно: уже установленные
версии доверяют только старому ключу.

Плановая ротация выполняется мостом:

1. выпустить старым ключом версию, в которую встроен новый публичный ключ;
2. дождаться обновления активных установок;
3. следующие версии подписывать новым приватным ключом;
4. сохранить старый ключ в защищённом архиве на период миграции.

При полной утрате старого ключа безопасное автообновление существующих
установок невозможно. Пользователям потребуется ручная установка версии с
новым публичным ключом.
