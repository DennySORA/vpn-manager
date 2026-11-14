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
        // What is left to read; every step cuts it after a markup's last character.
        let mut rest = text;
        while let Some(found) = rest.find('<') {
            let (chars, markup) = rest.split_at_checked(found).ok_or(Malformed)?;
            check_text(chars, !open.is_empty())?;
            rest = if let Some(body) = markup.strip_prefix("<?") {
                past(body, "?>")?
            } else if let Some(body) = markup.strip_prefix("<!--") {
                past(body, "-->")?
            } else if let Some(body) = markup.strip_prefix("<![CDATA[") {
                if open.is_empty() {
                    return Err(Malformed);
                }
                past(body, "]]>")?
            } else if markup.starts_with("<!") {
                // `<!DOCTYPE` (where entities are declared) and every other declaration.
                return Err(Malformed);
            } else if let Some(tag) = markup.strip_prefix("</") {
                let (name, after) = name_at(tag)?;
                let after = after
                    .trim_start_matches(SPACE)
                    .strip_prefix('>')
                    .ok_or(Malformed)?;
                let top = open.pop().ok_or(Malformed)?;
                if elements[top].name != name {
                    return Err(Malformed);
                }
                after
            } else {
                // A second root, or past the bounds.
                if (open.is_empty() && !elements.is_empty())
                    || elements.len() == MAX_ELEMENTS
                    || open.len() == MAX_DEPTH
                {
                    return Err(Malformed);
                }
                let (element, after, empty) = start_tag(markup, open.last().copied())?;
                if !empty {
                    open.push(elements.len());
                }
                elements.push(element);
                after
            };
        }
        check_text(rest, !open.is_empty())?;
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

/// The start tag at the beginning of `markup`: the element, the text after the tag, and whether
/// it is an empty-element tag (`/>`).
fn start_tag(markup: &str, parent: Option<usize>) -> Result<(Element<'_>, &str, bool), Malformed> {
    let (name, mut rest) = name_at(markup.strip_prefix('<').ok_or(Malformed)?)?;
    let mut attributes: Vec<(&str, &str)> = Vec::new();
    loop {
        let spaced = rest.trim_start_matches(SPACE);
        if let Some(after) = spaced.strip_prefix('>') {
            return Ok((element(name, parent, attributes), after, false));
        }
        if let Some(after) = spaced.strip_prefix("/>") {
            return Ok((element(name, parent, attributes), after, true));
        }
        // White space before every attribute.
        if spaced.len() == rest.len() || attributes.len() == MAX_ATTRIBUTES {
            return Err(Malformed);
        }
        let (attribute, after_name) = name_at(spaced)?;
        let after_eq = after_name
            .trim_start_matches(SPACE)
            .strip_prefix('=')
            .ok_or(Malformed)?;
        let mut quoted = after_eq.trim_start_matches(SPACE).chars();
        let Some(quote @ ('"' | '\'')) = quoted.next() else {
            return Err(Malformed);
        };
        let (value, after_value) = quoted.as_str().split_once(quote).ok_or(Malformed)?;
        if value.contains('<') || attributes.iter().any(|(n, _)| *n == attribute) {
            return Err(Malformed);
        }
        check_references(value)?;
        attributes.push((attribute, value));
        rest = after_value;
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

/// What follows the first `close` in `body` (a markup after its opening).
fn past<'t>(body: &'t str, close: &str) -> Result<&'t str, Malformed> {
    body.split_once(close)
        .map(|(_, after)| after)
        .ok_or(Malformed)
}

/// The name at the start of `text`, and the text after it.
fn name_at(text: &str) -> Result<(&str, &str), Malformed> {
    let end = text.find(|c: char| !is_name_char(c)).unwrap_or(text.len());
    let (name, rest) = text.split_at_checked(end).ok_or(Malformed)?;
    match name.chars().next() {
        Some(first) if is_name_start(first) => Ok((name, rest)),
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
        let (_, after) = rest.get(at..).and_then(reference).ok_or(Malformed)?;
        rest = after;
    }
    Ok(())
}

/// The reference at the start of `text` (which starts with `&`): the character it stands for
/// and the text after the reference.
fn reference(text: &str) -> Option<(char, &str)> {
    let end = text.bytes().take(MAX_REFERENCE).position(|b| b == b';')?;
    let (written, after) = text.split_at_checked(end + 1)?;
    let c = match written.strip_prefix('&')?.strip_suffix(';')? {
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
    Some((c, after))
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
    // `find` stops where a character starts, so the split always succeeds.
    while let Some((text, tail)) = rest.find(SPECIAL).and_then(|at| rest.split_at_checked(at)) {
        out.push_str(text);
        let mut chars = tail.chars();
        let special = chars.next();
        let after = chars.as_str();
        rest = match special {
            Some('&') => {
                if let Some((c, after_reference)) = reference(tail) {
                    out.push(c);
                    after_reference
                } else {
                    // Not reached: `parse` checked every reference.
                    out.push('&');
                    after
                }
            }
            // A line break is one space, CR LF included.
            Some('\r') => {
                out.push(' ');
                after.strip_prefix('\n').unwrap_or(after)
            }
            _ => {
                out.push(' ');
                after
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
