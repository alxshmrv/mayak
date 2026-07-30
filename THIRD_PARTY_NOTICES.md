# Сторонние компоненты

Маяк использует open-source компоненты, которые сохраняют собственные
авторские права и условия лицензий. Основной код Маяка распространяется по
MIT, но эта лицензия не заменяет лицензии зависимостей.

Точный воспроизводимый состав зафиксирован в:

- `package-lock.json` — JavaScript/TypeScript зависимости;
- `src-tauri/Cargo.lock` — Rust зависимости.

Основные прямые компоненты:

| Компонент | Назначение | Лицензия |
| --- | --- | --- |
| React / React DOM | интерфейс | MIT |
| Tauri | desktop runtime и API | Apache-2.0 OR MIT |
| Tauri Updater / Process plugins | подписанные обновления и перезапуск | Apache-2.0 OR MIT |
| Lucide React | интерфейсные иконки | ISC |
| Tokio | асинхронный runtime | MIT |
| rusqlite / SQLite | локальное хранилище | MIT / Public Domain |
| mdns-sd | локальное обнаружение | MIT OR Apache-2.0 |
| windows-rs | Windows Native Wi-Fi, IP Helper и системные API | MIT OR Apache-2.0 |
| minisign-verify / rustls | проверка подписи и TLS обновлений | MIT OR Apache-2.0 / Apache-2.0 OR ISC OR MIT |

`windows-rs` входит только в Windows-сборку. CoreWLAN, CoreLocation и другие
Apple frameworks являются системными компонентами macOS и не поставляются
внутри приложения как сторонние библиотеки.

Снимок `src-tauri/data/ieee-ma.tsv` сгенерирован из публичных реестров
назначений MA-L, MA-M и MA-S IEEE Registration Authority. Исходные реестры и
названия организаций сохраняют авторские права IEEE и их владельцев и не
переходят под MIT-лицензию кода Маяка. Актуальные исходные списки опубликованы
на <https://standards.ieee.org/products-programs/regauth/>.

Среди транзитивных зависимостей также встречаются MPL-2.0, CC-BY-4.0,
CC0-1.0, Unicode-3.0, BlueOak-1.0.0, 0BSD, Zlib, BSD, ISC, Unlicense и
Apache-2.0 WITH LLVM-exception. В частности:

- `lightningcss` — MPL-2.0;
- `cssparser`, `selectors`, `dtoa-short`, `option-ext` — MPL-2.0;
- `caniuse-lite` — CC-BY-4.0;
- ICU4X Unicode data/components — Unicode-3.0;
- `mdn-data` — CC0-1.0.

Исходные тексты лицензий доступны в соответствующих пакетах npm/Cargo и их
upstream-репозиториях. При распространении готового бинарника необходимо
включить полные тексты применимых лицензий для фактически вошедших в него
зависимостей. Этот файл — обзор, а не замена таких текстов.

Оригинальные скриншоты, иконка и маскот, находящиеся в этом репозитории,
включены в лицензию MIT проекта, если рядом с конкретным файлом не указано
иное.
