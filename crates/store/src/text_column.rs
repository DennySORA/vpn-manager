//! A [`Text`] in a TEXT column: its JSON (`{"en":…,"zh-TW":…,"ja":…}`). A value written before the interface had
//! three languages is a plain string; it reads back as the same words in every language.

use vpn_domain::Text;

pub fn to_column(text: &Text) -> String {
    serde_json::to_string(text).unwrap_or_default()
}

pub fn from_column(value: String) -> Text {
    match serde_json::from_str::<Text>(&value) {
        // A JSON string is a plain value that happens to be quoted: keep it as it was written.
        Ok(text) if !value.trim_start().starts_with('"') => text,
        _ => Text::verbatim(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_domain::tr;

    #[test]
    fn a_value_written_before_the_languages_reads_back_unchanged() {
        assert_eq!(
            from_column("磁碟已滿".to_owned()),
            Text::verbatim("磁碟已滿")
        );
        assert_eq!(
            from_column("\"quoted\"".to_owned()),
            Text::verbatim("\"quoted\"")
        );
        assert_eq!(
            from_column("{not json".to_owned()),
            Text::verbatim("{not json")
        );
        let text = tr!("Disk full", "磁碟已滿", "ディスクがいっぱいです");
        assert_eq!(from_column(to_column(&text)), text);
    }
}
