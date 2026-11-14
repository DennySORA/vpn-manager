// SPDX-License-Identifier: GPL-3.0-or-later

//! A small, strict reader for the two XML documents of the bootstrap (`act=user`,
//! `act=manifest`). It keeps what they need — elements, their parents and their attributes — and
//! refuses what a plain data document has no use for.
//!
//! - Well-formed only: one root element, matching end tags, quoted attribute values without
//!   `<`, white space before every attribute, no duplicate attribute, no control character
//!   other than tab, CR and LF.
//! - References: the five predefined entities (`&quot;` `&apos;` `&lt;` `&gt;` `&amp;`) and
//!   character references (`&#10;`, `&#xA;`; serializers write them for line breaks inside
//!   attributes). Any other entity, and any `<!DOCTYPE` (where entities would be declared), is
//!   refused: nothing ever expands.
//! - Comments, processing instructions (the `<?xml …?>` declaration) and CDATA sections are
//!   skipped; text is checked but not kept (both documents carry their data in attributes).
//! - Bounded: nesting depth, element count and attributes per element; one linear pass.
//!
//! Values stay borrowed from the decrypted buffer and are decoded only when read, so attributes
//! nobody asks for (the account's `OpenVPN` keys) are never copied.

use std::borrow::Cow;

/// `manifest/servers/server` is three deep; anything near this is not the contract.
const MAX_DEPTH: usize = 16;
/// 2048 servers plus modes, groups and messages fit many times over.
const MAX_ELEMENTS: usize = 32 * 1024;
const MAX_ATTRIBUTES: usize = 128;
/// Longest reference accepted: `&#x10FFFF;`.
const MAX_REFERENCE: usize = 10;
/// XML white space (`S`).
const SPACE: [char; 4] = [' ', '\t', '\n', '\r'];

/// The document is not well-formed, or uses something this reader refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

/// A parsed document: its elements in document order, the root first.
pub struct Document<'a> {
    elements: Vec<Element<'a>>,
}

pub struct Element<'a> {
    name: &'a str,
    parent: Option<usize>,
    /// Names and raw values (the text between the quotes, references not decoded).
    attributes: Vec<(&'a str, &'a str)>,
}

impl<'a> Document<'a> {
    pub(crate) fn parse(text: &'a str) -> Result<Self, Malformed> {
        // XML 1.0 §2.2: no control characters but tab, line feed and carriage return.
        if text
            .bytes()
            .any(|b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r'))
        {
            return Err(Malformed);
        }
        let text = text.trim_prefix('\u{feff}');
        let mut elements: Vec<Element<'a>> = Vec::new();
        let mut open: Vec<usize> = Vec::new();
        let mut pos = 0;
        while let Some(found) = text[pos..].find('<') {
            let start = pos + found;
            check_text(&text[pos..start], !open.is_empty())?;
            let markup = &text[start..];
            let len = if markup.starts_with("<?") {
                past(markup, 2, "?>")?
            } else if markup.starts_with("<!--") {
                past(markup, 4, "-->")?
            } else if markup.starts_with("<![CDATA[") {
                if open.is_empty() {
                    return Err(Malformed);
                }
                past(markup, 9, "]]>")?
            } else if markup.starts_with("<!") {
                // `<!DOCTYPE` (where entities are declared) and every other declaration.
                return Err(Malformed);
            } else if let Some(tag) = markup.strip_prefix("</") {
                let name = name_at(tag)?;
                let rest = &tag[name.len()..];
                let gap = rest.len() - rest.trim_start_matches(SPACE).len();
                if !rest[gap..].starts_with('>') {
                    return Err(Malformed);
                }
                let top = open.pop().ok_or(Malformed)?;
                if elements[top].name != name {
                    return Err(Malformed);
                }
                2 + name.len() + gap + 1
            } else {
                // A second root, or past the bounds.
                if (open.is_empty() && !elements.is_empty())
                    || elements.len() == MAX_ELEMENTS
                    || open.len() == MAX_DEPTH
                {
                    return Err(Malformed);
                }
                let (element, len, empty) = start_tag(markup, open.last().copied())?;
                if !empty {
                    open.push(elements.len());
                }
                elements.push(element);
                len
            };
            pos = start + len;
        }
        check_text(&text[pos..], !open.is_empty())?;
        if !open.is_empty() || elements.is_empty() {
            return Err(Malformed);
        }
        Ok(Self { elements })
    }

    /// The document element.
    pub(crate) fn root(&self) -> &Element<'a> {
        // `parse` never returns an empty document.
        &self.elements[0]
    }

    /// Elements named `name` whose parent is named `parent`, in document order: `XPath`
    /// `//parent/name`, as Eddie selects modes, server groups and servers.
    pub(crate) fn select(&self, parent: &str, name: &str) -> impl Iterator<Item = &Element<'a>> {
        self.elements.iter().filter(move |element| {
            element.name == name
                && element
                    .parent
                    .is_some_and(|p| self.elements[p].name == parent)
        })
    }

    /// Elements at `root/path[0]/path[1]/…`, in document order: Eddie's `SelectNodes("keys/key")`
    /// on the document element.
    pub(crate) fn path(&self, path: &[&str]) -> impl Iterator<Item = &Element<'a>> {
        self.elements.iter().filter(move |element| {
            let mut current = *element;
            for (step, name) in path.iter().rev().enumerate() {
                let Some(parent) = current.parent.filter(|_| current.name == *name) else {
                    return false;
                };
                if step + 1 == path.len() {
                    return parent == 0;
                }
                current = &self.elements[parent];
            }
            false
        })
    }
}

impl<'a> Element<'a> {
    pub(crate) const fn name(&self) -> &'a str {
        self.name
    }

    /// The attribute's text exactly as written, references not decoded. For values that may be
    /// secret: base64 never needs decoding, so nothing is copied.
    pub(crate) fn raw(&self, name: &str) -> Option<&'a str> {
        self.attributes
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, value)| *value)
    }

    /// The attribute's value: references decoded, literal tabs and line breaks turned into
    /// spaces (XML 1.0 §3.3.3).
    pub(crate) fn get(&self, name: &str) -> Option<Cow<'a, str>> {
        self.raw(name).map(decode)
    }
}

/// The start tag at the beginning of `markup`: the element, the tag's length, and whether it is
/// an empty-element tag (`/>`).
fn start_tag(markup: &str, parent: Option<usize>) -> Result<(Element<'_>, usize, bool), Malformed> {
    let name = name_at(&markup[1..])?;
    let mut at = 1 + name.len();
    let mut attributes: Vec<(&str, &str)> = Vec::new();
    loop {
        let rest = &markup[at..];
        let gap = rest.len() - rest.trim_start_matches(SPACE).len();
        let rest = &rest[gap..];
        at += gap;
        if rest.starts_with('>') {
            return Ok((element(name, parent, attributes), at + 1, false));
        }
        if rest.starts_with("/>") {
            return Ok((element(name, parent, attributes), at + 2, true));
        }
        if gap == 0 || attributes.len() == MAX_ATTRIBUTES {
            return Err(Malformed);
        }
        let attribute = name_at(rest)?;
        let after_name = &rest[attribute.len()..];
        let before_eq = after_name.len() - after_name.trim_start_matches(SPACE).len();
        let after_eq = after_name[before_eq..].strip_prefix('=').ok_or(Malformed)?;
        let before_quote = after_eq.len() - after_eq.trim_start_matches(SPACE).len();
        let quoted = &after_eq[before_quote..];
        let Some(quote @ ('"' | '\'')) = quoted.chars().next() else {
            return Err(Malformed);
        };
        let value_len = quoted[1..].find(quote).ok_or(Malformed)?;
        let value = &quoted[1..=value_len];
        if value.contains('<') || attributes.iter().any(|(n, _)| *n == attribute) {
            return Err(Malformed);
        }
        check_references(value)?;
        attributes.push((attribute, value));
        at += attribute.len() + before_eq + 1 + before_quote + value_len + 2;
    }
}

const fn element<'a>(
    name: &'a str,
    parent: Option<usize>,
    attributes: Vec<(&'a str, &'a str)>,
) -> Element<'a> {
    Element {
        name,
        parent,
        attributes,
    }
}

/// Length of `markup` through the first `close` after its first `skip` bytes.
fn past(markup: &str, skip: usize, close: &str) -> Result<usize, Malformed> {
    markup[skip..]
        .find(close)
        .map(|at| skip + at + close.len())
        .ok_or(Malformed)
}

/// The name at the start of `text`.
fn name_at(text: &str) -> Result<&str, Malformed> {
    let end = text.find(|c: char| !is_name_char(c)).unwrap_or(text.len());
    let name = &text[..end];
    match name.chars().next() {
        Some(first) if is_name_start(first) => Ok(name),
        _ => Err(Malformed),
    }
}

const fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == ':' || !c.is_ascii()
}

const fn is_name_char(c: char) -> bool {
    is_name_start(c) || c.is_ascii_digit() || c == '-' || c == '.'
}

/// Character data: only white space outside the root element; valid references inside it.
fn check_text(text: &str, inside: bool) -> Result<(), Malformed> {
    if inside {
        check_references(text)
    } else if text.chars().all(|c| SPACE.contains(&c)) {
        Ok(())
    } else {
        Err(Malformed)
    }
}

fn check_references(text: &str) -> Result<(), Malformed> {
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        let (_, len) = reference(&rest[at..]).ok_or(Malformed)?;
        rest = &rest[at + len..];
    }
    Ok(())
}

/// The reference at the start of `text` (which starts with `&`): the character it stands for
/// and the reference's length.
fn reference(text: &str) -> Option<(char, usize)> {
    let end = text.bytes().take(MAX_REFERENCE).position(|b| b == b';')?;
    let c = match &text[1..end] {
        "quot" => '"',
        "apos" => '\'',
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        body => {
            let (digits, radix) = match body.strip_prefix("#x") {
                Some(hex) => (hex, 16),
                None => (body.strip_prefix('#')?, 10),
            };
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return None;
            }
            let c = char::from_u32(u32::from_str_radix(digits, radix).ok()?)?;
            if !is_xml_char(c) {
                return None;
            }
            c
        }
    };
    Some((c, end + 1))
}

/// XML 1.0 `Char` (surrogates cannot be a `char`).
const fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

/// Attribute value normalization (XML 1.0 §2.11, §3.3.3) of a value `parse` accepted.
fn decode(raw: &str) -> Cow<'_, str> {
    const SPECIAL: [char; 4] = ['&', '\t', '\n', '\r'];
    if !raw.contains(SPECIAL) {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find(SPECIAL) {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        rest = match tail.as_bytes()[0] {
            b'&' => {
                if let Some((c, len)) = reference(tail) {
                    out.push(c);
                    &tail[len..]
                } else {
                    // Not reached: `parse` checked every reference.
                    out.push('&');
                    &tail[1..]
                }
            }
            // A line break is one space, CR LF included.
            b'\r' if tail[1..].starts_with('\n') => {
                out.push(' ');
                &tail[2..]
            }
            _ => {
                out.push(' ');
                &tail[1..]
            }
        };
    }
    out.push_str(rest);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {

    use super::*;

    fn parse(text: &str) -> Result<Document<'_>, Malformed> {
        Document::parse(text)
    }

    #[test]
    fn markup_beyond_plain_data_is_refused() {
        for bad in [
            "",
            "   ",
            "text",
            "<!DOCTYPE user [<!ENTITY x \"y\">]><user/>",
            "<!ENTITY x \"y\"><user/>",
            "<user v=\"&x;\"/>",
            "<user v=\"&nbsp;\"/>",
            "<user v=\"a & b\"/>",
            "<user v=\"&#0;\"/>",
            "<user v=\"&#xD800;\"/>",
            "<user v=\"&#x110000;\"/>",
            "<user v=\"&#+65;\"/>",
            "<user v=\"&#X41;\"/>",
            "<user v=\"&#1234567890;\"/>",
            "<user>&bogus;</user>",
            "<user v=\"<\"/>",
            "<user v=\"1\" v=\"2\"/>",
            "<user v=\"1\"w=\"2\"/>",
            "<user v=1/>",
            "<user v=\"1/>",
            "<user",
            "<user>",
            "<user></users>",
            "<a><b></a></b>",
            "<user/><user/>",
            "<user/>trailing",
            "<![CDATA[x]]><user/>",
            "<user>\u{1}</user>",
            "<user v=\"\u{0}\"/>",
            "<1user/>",
            "<user -v=\"1\"/>",
            "<!-- unterminated <user/>",
            "<?xml version=\"1.0\"<user/>",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
