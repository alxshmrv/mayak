use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Ошибка локального файла: {0}")]
    Io(#[from] std::io::Error),

    #[error("Не удалось получить данные macOS: {0}")]
    Platform(String),

    #[error("Не удалось прочитать сетевую конфигурацию: {0}")]
    Network(String),

    #[error("Ошибка локального хранилища: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("Ошибка сериализации данных: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Сканирование уже выполняется")]
    ScanInProgress,

    #[error("Mac не подключён к Wi‑Fi")]
    NoWifi,

    #[error("В текущей Wi‑Fi-сети нет доступного IPv4-адреса")]
    NoIpv4,
}

pub type AppResult<T> = Result<T, AppError>;
