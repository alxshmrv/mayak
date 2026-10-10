use thiserror::Error;

use crate::i18n::Language;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Local file error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Could not read system network data: {0}")]
    Platform(String),

    #[error("Could not read the network configuration: {0}")]
    Network(String),

    #[error("Local storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("Data serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("A scan is already running")]
    ScanInProgress,

    #[error("This computer is not connected to Wi‑Fi")]
    NoWifi,

    #[error("The current Wi‑Fi network has no IPv4 address")]
    NoIpv4,
}

impl AppError {
    /// User-facing message in the interface language. `Display` stays English for logs.
    pub fn message(&self, language: Language) -> String {
        if language == Language::En {
            return self.to_string();
        }
        match self {
            Self::Io(error) => format!("Ошибка локального файла: {error}"),
            Self::Platform(detail) => {
                format!("Не удалось получить системные сетевые данные: {detail}")
            }
            Self::Network(detail) => format!("Не удалось прочитать сетевую конфигурацию: {detail}"),
            Self::Storage(error) => format!("Ошибка локального хранилища: {error}"),
            Self::Serialization(error) => format!("Ошибка сериализации данных: {error}"),
            Self::ScanInProgress => "Сканирование уже выполняется".to_owned(),
            Self::NoWifi => "Компьютер не подключён к Wi‑Fi".to_owned(),
            Self::NoIpv4 => "В текущей Wi‑Fi-сети нет доступного IPv4-адреса".to_owned(),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
