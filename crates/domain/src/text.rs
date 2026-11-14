//! Text a person reads, in every language of the interface: English, Traditional Chinese and Japanese.
//!
//! What the service writes for people — errors, validation problems, faults, reasons, the descriptions of built-in
//! items — is a [`Text`]: the three languages travel together over the API, between the processes and into the
//! databases, and whoever shows one picks its language (the web UI its own, `vpnctl` Traditional Chinese, the logs
//! English). Write one with [`tr!`](crate::tr); text that is the same in every language — an operating system's
//! error, a provider's own words, a path or a name — is [`Text::verbatim`].
//!
//! On the wire a `Text` is `{"en": …, "zh-TW": …, "ja": …}` ([`Translations`]). A plain string is read as verbatim text: that is how
//! records written before the interface had three languages come back.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// One sentence (or label) in the three languages of the interface. It is one pointer wide: the words live
/// behind it, so the errors and records that carry one stay small.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(transparent)]
#[ts(export)]
pub struct Text(Box<Translations>);

/// The words of a [`Text`]: `{"en": …, "zh-TW": …, "ja": …}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(from = "Stored")]
#[ts(export)]
pub struct Translations {
    pub en: String,
    #[serde(rename = "zh-TW")]
    pub zh_tw: String,
    pub ja: String,
}

/// The languages a [`Text`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    English,
    TraditionalChinese,
    Japanese,
}

impl Language {
    /// The language to answer a request in by its `Accept-Language` values: the first language of the
    /// interface they list (any Chinese is Traditional Chinese, as in the web UI; one refused with `q=0` is
    /// skipped), else English — the web UI's choice for a reader whose languages it does not have.
    pub fn of_accept_language<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        values
            .into_iter()
            .find_map(Self::first_accepted)
            .unwrap_or(Self::English)
    }

    fn first_accepted(value: &str) -> Option<Self> {
        value.split(',').find_map(|item| {
            let mut parts = item.split(';');
            let tag = parts.next()?.trim();
            let refused = parts.any(|p| {
                p.trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            });
            if refused {
                return None;
            }
            let primary = tag.split('-').next()?;
            if primary.eq_ignore_ascii_case("zh") {
                Some(Self::TraditionalChinese)
            } else if primary.eq_ignore_ascii_case("ja") {
                Some(Self::Japanese)
            } else if primary.eq_ignore_ascii_case("en") {
                Some(Self::English)
            } else {
                None
            }
        })
    }
}

impl Deref for Text {
    type Target = Translations;

    fn deref(&self) -> &Translations {
        &self.0
    }
}

impl Text {
    #[must_use]
    pub fn new(en: String, zh_tw: String, ja: String) -> Self {
        Self(Box::new(Translations { en, zh_tw, ja }))
    }

    /// The same words in every language: a name, a path, an error the operating system or a provider wrote.
    pub fn verbatim(text: impl Into<String>) -> Self {
        let text = text.into();
        Self::new(text.clone(), text.clone(), text)
    }

    #[must_use]
    pub fn get(&self, language: Language) -> &str {
        match language {
            Language::English => &self.0.en,
            Language::TraditionalChinese => &self.0.zh_tw,
            Language::Japanese => &self.0.ja,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.en.is_empty() && self.0.zh_tw.is_empty() && self.0.ja.is_empty()
    }

    /// Each language changed the same way (`f` gets the language and its text).
    #[must_use]
    pub fn map(&self, mut f: impl FnMut(Language, &str) -> String) -> Self {
        Self::new(
            f(Language::English, &self.0.en),
            f(Language::TraditionalChinese, &self.0.zh_tw),
            f(Language::Japanese, &self.0.ja),
        )
    }
}

impl From<String> for Text {
    fn from(text: String) -> Self {
        Self::verbatim(text)
    }
}

/// A [`Text`] where an error is expected — inside an `io::Error`, say, or as the source of
/// another error. Its `Display` is the English (for logs); [`Text::of_io_error`] gets the words
/// back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextError(pub Text);

impl std::fmt::Display for TextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.en)
    }
}

impl std::error::Error for TextError {}

impl Text {
    /// An I/O error that carries these words ([`TextError`]).
    #[must_use]
    pub fn into_io_error(self, kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::new(kind, TextError(self))
    }

    /// The words of an I/O error for people: the [`Text`] it carries ([`TextError`]), else its
    /// own message, as it is (an operating system's error reads the same in every language).
    #[must_use]
    pub fn of_io_error(e: &std::io::Error) -> Self {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<TextError>())
            .map_or_else(|| Self::verbatim(e.to_string()), |t| t.0.clone())
    }
}

impl From<&str> for Text {
    fn from(text: &str) -> Self {
        Self::verbatim(text)
    }
}

/// What may be read back: the three languages, or one plain string from before they existed.
#[derive(Deserialize)]
#[serde(untagged)]
enum Stored {
    Languages {
        en: String,
        #[serde(rename = "zh-TW")]
        zh_tw: String,
        ja: String,
    },
    Plain(String),
}

impl From<Stored> for Translations {
    fn from(stored: Stored) -> Self {
        match stored {
            Stored::Languages { en, zh_tw, ja } => Self { en, zh_tw, ja },
            Stored::Plain(text) => Self {
                en: text.clone(),
                zh_tw: text.clone(),
                ja: text,
            },
        }
    }
}

/// A [`Text`] in the three languages: `tr!("English", "繁體中文", "日本語")`.
///
/// Values are written into the strings as in `format!`, by name (`{name}`, `{count:>3}`): every name is a variable
/// in scope. A value that is itself a [`Text`] (or anything `Into<Text>`) is named after a `;`, and each language
/// takes its own words:
///
/// ```
/// # use vpn_domain::tr;
/// let path = "/srv/in";
/// let why = tr!("not found", "找不到", "見つかりません");
/// let text = tr!("{path}: {why}", "{path}：{why}", "{path}：{why}"; why = why);
/// assert_eq!(text.zh_tw, "/srv/in：找不到");
/// ```
#[macro_export]
macro_rules! tr {
    ($en:literal, $zh:literal, $ja:literal $(,)?) => {
        $crate::text::Text::new(::std::format!($en), ::std::format!($zh), ::std::format!($ja))
    };
    ($en:literal, $zh:literal, $ja:literal; $($name:ident = $value:expr),+ $(,)?) => {{
        $( let $name: $crate::text::Text = ::std::convert::Into::into($value); )+
        $crate::text::Text::new(
            {
                $( let $name = $name.en.as_str(); let _ = $name; )+
                ::std::format!($en)
            },
            {
                $( let $name = $name.zh_tw.as_str(); let _ = $name; )+
                ::std::format!($zh)
            },
            {
                $( let $name = $name.ja.as_str(); let _ = $name; )+
                ::std::format!($ja)
            },
        )
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_from_before_the_languages_reads_as_the_same_words_in_each() {
        let old: Text = serde_json::from_str(r#""名稱需要 1–64 個字元""#).unwrap();
        assert_eq!(old, Text::verbatim("名稱需要 1–64 個字元"));
        let new = tr!(
            "Needs 1–64 characters",
            "需要 1–64 個字元",
            "1〜64 文字にしてください"
        );
        let json = serde_json::to_string(&new).unwrap();
        assert_eq!(
            json,
            r#"{"en":"Needs 1–64 characters","zh-TW":"需要 1–64 個字元","ja":"1〜64 文字にしてください"}"#
        );
        assert_eq!(serde_json::from_str::<Text>(&json).unwrap(), new);
    }

    #[test]
    fn a_text_value_is_written_in_each_language_of_its_own() {
        let count = 3;
        let why = tr!("busy", "忙碌", "使用中");
        let text = tr!("{count} items: {why}", "{count} 項：{why}", "{count} 件：{why}"; why = why);
        assert_eq!(text.en, "3 items: busy");
        assert_eq!(text.zh_tw, "3 項：忙碌");
        assert_eq!(text.ja, "3 件：使用中");
        assert_eq!(size_of::<Text>(), size_of::<usize>());
        assert_eq!(
            Language::of_accept_language(["fr-FR, ja;q=0.8"]),
            Language::Japanese
        );
        assert_eq!(
            Language::of_accept_language(["zh-CN"]),
            Language::TraditionalChinese
        );
        assert_eq!(
            Language::of_accept_language(["ja;q=0, fr"]),
            Language::English
        );
        assert_eq!(Language::of_accept_language([]), Language::English);
        let plain = tr!("at {path}", "位於 {path}", "{path} にあります"; path = "/srv");
        assert_eq!(plain.get(Language::Japanese), "/srv にあります");
    }
}
