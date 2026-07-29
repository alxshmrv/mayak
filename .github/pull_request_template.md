## Что изменено

Кратко опишите проблему и решение.

## Как проверено

- [ ] `npm run check`
- [ ] `cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check`
- [ ] `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings`
- [ ] `cargo test --manifest-path src-tauri/Cargo.toml --all-targets`

## Безопасность и приватность

- [ ] Изменение не публикует реальные сетевые или персональные данные.
- [ ] Новые сетевые проверки ограничены текущей локальной подсетью и имеют
      таймауты.
- [ ] Новые зависимости и разрешения объяснены.
