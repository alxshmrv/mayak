use serde::{Deserialize, Serialize};

/// Language used for text the native side generates: findings, device names,
/// scan progress, errors, the tray menu, and notifications.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Ru,
    En,
}

impl Language {
    /// Picks the Russian or English variant of a static string.
    pub const fn pick(self, ru: &'static str, en: &'static str) -> &'static str {
        match self {
            Self::Ru => ru,
            Self::En => en,
        }
    }

    /// Russian for a Russian OS locale, English for everything else.
    pub fn system() -> Self {
        sys_locale::get_locale().map_or(Self::En, |locale| Self::from_locale(&locale))
    }

    fn from_locale(locale: &str) -> Self {
        if locale.to_ascii_lowercase().starts_with("ru") {
            Self::Ru
        } else {
            Self::En
        }
    }
}

/// The language the user chose in settings.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LanguagePreference {
    #[default]
    System,
    Ru,
    En,
}

impl LanguagePreference {
    pub fn resolve(self) -> Language {
        match self {
            Self::System => Language::system(),
            Self::Ru => Language::Ru,
            Self::En => Language::En,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Language, LanguagePreference};

    #[test]
    fn only_russian_locales_select_russian() {
        assert_eq!(Language::from_locale("ru-RU"), Language::Ru);
        assert_eq!(Language::from_locale("ru"), Language::Ru);
        assert_eq!(Language::from_locale("en-US"), Language::En);
        assert_eq!(Language::from_locale("uk-UA"), Language::En);
    }

    #[test]
    fn explicit_preference_ignores_the_system_locale() {
        assert_eq!(LanguagePreference::Ru.resolve(), Language::Ru);
        assert_eq!(LanguagePreference::En.resolve(), Language::En);
    }

    #[test]
    fn settings_without_language_default_to_system() {
        let value: LanguagePreference = serde_json::from_str("\"system\"").unwrap();
        assert_eq!(value, LanguagePreference::default());
    }
}
