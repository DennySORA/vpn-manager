// SPDX-License-Identifier: GPL-3.0-or-later

//! Just enough HTML for `AirVPN`'s sign-in and Ports pages: start and end tags with their
//! attributes, the sign-in form, an element's `data-json`, the text of an error message, and a
//! scrubbed snippet for the debug log.
//!
//! Not an HTML parser: one bounded, linear scan for tags that skips comments, declarations and
//! the contents of `<script>` and `<style>`. Attribute values stay borrowed from the page (which
//! sits in a zeroizing buffer) and are decoded only when read; the page token is decoded into a
//! zeroizing buffer of its own. Nothing is ever executed or followed.

use std::borrow::Cow;
use std::ops::Range;

use zeroize::Zeroizing;

/// Tags scanned before giving up; a large page has a few thousand.
const MAX_TAGS: usize = 50_000;
/// Attributes kept per tag; the rest are skipped.
const MAX_ATTRIBUTES: usize = 64;
/// Longest error message text kept (before it is checked for being a plain sentence).
const MAX_MESSAGE: usize = 600;
/// Longest snippet written to the debug log.
const SNIPPET: usize = 160;

/// Words of a page that only a CAPTCHA puts there.
const CAPTCHA: &[&str] = &["captcha", "g-recaptcha", "h-captcha", "cf-turnstile"];
/// Words of a second sign-in step (IPS multi-factor authentication or `AirVPN`'s own).
const SECOND_FACTOR: &[&str] = &[
    "two-factor",
    "two factor",
    "two-step",
    "two step",
    "2-step",
    "2fa",
    "verification code",
    "authentication code",
    "authenticator",
    "security question",
];
/// Field names of a second sign-in step.
const SECOND_FACTOR_FIELDS: &[&str] = &[
    "mfa",
    "otp",
    "auth_code",
    "authcode",
    "2fa",
    "twofactor",
    "authenticator",
    "security_answer",
    "verification",
];
/// What a signed-out answer says (`AirVPN`'s Ports page says "Login required.").
const SIGNED_OUT: &[&str] = &[
    "login required",
    "not logged in",
    "not signed in",
    "please log in",
    "please sign in",
    "must be logged in",
    "must be signed in",
    "session expired",
    "session has expired",
];
/// What an answer to a stale page token says.
const STALE_TOKEN: &[&str] = &[
    "ecsrf",
    "csrf",
    "security key",
    "security token",
    "invalid token",
];
/// What a sign-in refused for too many attempts says.
const LOCKED: &[&str] = &[
    "locked",
    "too many",
    "try again in",
    "temporarily",
    "lockout",
];

/// One tag as written: its name, whether it closes, and its attributes (raw values).
pub(super) struct Tag<'a> {
    name: &'a str,
    pub(super) end: bool,
    attrs: Vec<(&'a str, Option<&'a str>)>,
    /// Where the tag is in the page.
    pub(super) span: Range<usize>,
}

impl<'a> Tag<'a> {
    pub(super) const fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    /// The attribute's value, entities decoded; `Some("")` for a bare attribute.
    pub(super) fn attr(&self, name: &str) -> Option<Cow<'a, str>> {
        self.entry(name).map(|(_, v)| decode(v.unwrap_or_default()))
    }

    pub(super) fn has(&self, name: &str) -> bool {
        self.entry(name).is_some()
    }

    /// The raw (undecoded) value of attribute `name`; `None` when it is absent or has no value.
    fn raw(&self, name: &str) -> Option<&'a str> {
        self.entry(name).and_then(|(_, v)| *v)
    }

    /// The attribute `name` with its raw value, when the tag has it.
    fn entry(&self, name: &str) -> Option<&(&'a str, Option<&'a str>)> {
        self.attrs
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
    }

    /// Whether the `class` attribute names `class`.
    fn has_class(&self, class: &str) -> bool {
        self.attr("class")
            .is_some_and(|c| c.split_ascii_whitespace().any(|c| c == class))
    }
}

/// The tags of `page`, in order.
pub(super) fn tags(page: &str) -> Vec<Tag<'_>> {
    let b = page.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < MAX_TAGS {
        let Some(rel) = b
            .get(i..)
            .and_then(|rest| rest.iter().position(|&c| c == b'<'))
        else {
            break;
        };
        let at = i + rel;
        let rest = &b[at..];
        if rest.starts_with(b"<!--") {
            i = find(b, at + 4, b"-->").map_or(b.len(), |e| e + 3);
            continue;
        }
        if rest.starts_with(b"<!") || rest.starts_with(b"<?") {
            i = find(b, at, b">").map_or(b.len(), |e| e + 1);
            continue;
        }
        let end = rest.starts_with(b"</");
        let name_at = at + if end { 2 } else { 1 };
        if !b.get(name_at).is_some_and(u8::is_ascii_alphabetic) {
            i = at + 1;
            continue;
        }
        let mut j = name_at;
        while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'>' && b[j] != b'/' {
            j += 1;
        }
        let name = &page[name_at..j];
        let mut attrs = Vec::new();
        loop {
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            match b.get(j) {
                None => break,
                Some(b'>') => {
                    j += 1;
                    break;
                }
                Some(b'/') => {
                    j += 1;
                    continue;
                }
                Some(_) => {}
            }
            let name_from = j;
            while j < b.len() && !b[j].is_ascii_whitespace() && !matches!(b[j], b'=' | b'>' | b'/')
            {
                j += 1;
            }
            let attr = &page[name_from..j];
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            let value = if b.get(j) == Some(&b'=') {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if let Some(&q @ (b'"' | b'\'')) = b.get(j) {
                    let from = j + 1;
                    let to = find(b, from, &[q]).unwrap_or(b.len());
                    j = (to + 1).min(b.len());
                    Some(&page[from..to])
                } else {
                    let from = j;
                    while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'>' {
                        j += 1;
                    }
                    Some(&page[from..j])
                }
            } else {
                None
            };
            if attrs.len() < MAX_ATTRIBUTES && !attr.is_empty() {
                attrs.push((attr, value));
            }
        }
        let raw_text =
            !end && (name.eq_ignore_ascii_case("script") || name.eq_ignore_ascii_case("style"));
        out.push(Tag {
            name,
            end,
            attrs,
            span: at..j,
        });
        i = j;
        if raw_text {
            // Their content is text, never markup: resume at their end tag.
            let close = if name.eq_ignore_ascii_case("script") {
                b"</script".as_slice()
            } else {
                b"</style".as_slice()
            };
            i = find_ci(b, j, close).unwrap_or(b.len());
        }
    }
    out
}

/// First `needle` at or after `from`.
fn find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// [`find`], ignoring ASCII case.
fn find_ci(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
        .map(|p| from + p)
}

/// Entities decoded: the named ones a page writes in attributes and text, and numeric ones. An
/// unknown or broken reference stays as written.
pub(super) fn decode(raw: &str) -> Cow<'_, str> {
    if !raw.contains('&') {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    decode_into(raw, &mut out);
    Cow::Owned(out)
}

fn decode_into(raw: &str, out: &mut String) {
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let reference = rest
            .get(1..rest.len().min(12))
            .and_then(|r| r.find(';'))
            .map(|semi| &rest[1..=semi]);
        let decoded = reference.and_then(|r| match r {
            "quot" => Some('"'),
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ => {
                let number = r.strip_prefix('#')?;
                let code = match number.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                    None => number.parse().ok()?,
                };
                char::from_u32(code).filter(|c| *c != '\0')
            }
        });
        if let (Some(r), Some(c)) = (reference, decoded) {
            out.push(c);
            rest = &rest[r.len() + 2..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
}

// -------------------------------------------------------------------------------------------
// The sign-in form
// -------------------------------------------------------------------------------------------

/// The sign-in form as the page offers it.
#[derive(Debug)]
pub(super) struct LoginForm {
    /// Where it posts (origin-form path).
    pub(super) action: String,
    /// Its hidden fields in page order (`csrfKey`, and `ref` when the page has one).
    pub(super) hidden: Vec<(String, String)>,
    /// The submit button's name and value (`_processLogin=usernamepassword`).
    pub(super) submit: (String, String),
    /// The form offers "Sign in anonymously" (`anonymous`).
    pub(super) anonymous: bool,
}

/// Why a page's sign-in form cannot be used.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum FormProblem {
    /// No sign-in form at all.
    NoForm,
    /// A sign-in form without this field.
    Missing(&'static str),
    /// The form shows a CAPTCHA.
    Captcha,
    /// The form asks for something this client does not know how to fill.
    UnknownField(String),
}

/// The account name field (the page labels it "Display Name or Email Address").
pub(super) const AUTH: &str = "auth";
pub(super) const PASSWORD: &str = "password";
const CSRF_KEY: &str = "csrfKey";
const SUBMIT: &str = "_processLogin";
/// The submit value of the password sign-in among IPS's handlers.
const PASSWORD_HANDLER: &str = "usernamepassword";
const REMEMBER_ME: &str = "remember_me";
const ANONYMOUS: &str = "anonymous";

/// One field of a form.
struct Field {
    tag: &'static str,
    kind: String,
    name: String,
    value: String,
}

/// The origin-form path of a form `action` on airvpn.org; `None` for another site.
fn action_path(action: &str) -> Option<String> {
    let path = if let Some(rest) = action.strip_prefix("https://airvpn.org") {
        rest
    } else if let Some(rest) = action.strip_prefix("//airvpn.org") {
        rest
    } else if action.starts_with('/') && !action.starts_with("//") {
        action
    } else {
        return None;
    };
    let path = if path.is_empty() { "/" } else { path };
    path.starts_with('/').then(|| path.to_owned())
}

/// Whether `path` is the sign-in page.
pub(super) fn is_login_path(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    path == "/login/" || path == "/login"
}

/// The page's sign-in form: the first form that posts to `/login/` with an account name and a
/// password field.
pub(super) fn login_form(page: &str) -> Result<LoginForm, FormProblem> {
    let tags = tags(page);
    let mut problem = FormProblem::NoForm;
    let mut i = 0;
    while i < tags.len() {
        let tag = &tags[i];
        i += 1;
        if tag.end || !tag.is("form") {
            continue;
        }
        let post = tag
            .attr("method")
            .is_some_and(|m| m.eq_ignore_ascii_case("post"));
        let action = tag.attr("action").and_then(|a| action_path(&a));
        let opens = tag.span.start;
        let (fields, closes) = form_fields(&tags, &mut i, page.len());
        let Some(action) = action.filter(|a| post && is_login_path(a)) else {
            continue;
        };
        let has = |name: &str| fields.iter().any(|f| f.name == name);
        let password_field = fields
            .iter()
            .any(|f| f.name == PASSWORD && f.kind == "password");
        if !has(AUTH) && !password_field {
            continue; // another form to /login/ (a social sign-in button)
        }
        if has_any(&page[opens..closes], CAPTCHA) {
            return Err(FormProblem::Captcha);
        }
        problem = match () {
            () if !has(AUTH) => FormProblem::Missing("auth"),
            () if !password_field => FormProblem::Missing("password"),
            () if !fields
                .iter()
                .any(|f| f.name == CSRF_KEY && f.kind == "hidden") =>
            {
                FormProblem::Missing("csrfKey")
            }
            () => match complete_form(action, &fields, has(ANONYMOUS)) {
                Ok(form) => return Ok(form),
                Err(problem) => problem,
            },
        };
    }
    Err(problem)
}

/// The fields of the form whose opening tag precedes `tags[*i]`, advancing `*i` past its end,
/// and where the form's content ends (`page_len` when it is never closed).
fn form_fields(tags: &[Tag<'_>], i: &mut usize, page_len: usize) -> (Vec<Field>, usize) {
    let mut fields = Vec::new();
    let mut closes = page_len;
    while *i < tags.len() {
        let t = &tags[*i];
        *i += 1;
        if t.is("form") {
            if !t.end {
                *i -= 1; // a form never nests: this one ends here
            }
            closes = t.span.start;
            break;
        }
        if t.end {
            continue;
        }
        let (kind, default) = if t.is("input") {
            ("input", "text")
        } else if t.is("button") {
            ("button", "submit")
        } else if t.is("select") {
            ("select", "select")
        } else if t.is("textarea") {
            ("textarea", "textarea")
        } else {
            continue;
        };
        let Some(name) = t.attr("name").filter(|n| !n.is_empty()) else {
            continue;
        };
        if t.has("disabled") {
            continue;
        }
        let checkbox_off = t.attr("type").is_some_and(|ty| {
            ty.eq_ignore_ascii_case("checkbox") || ty.eq_ignore_ascii_case("radio")
        }) && !t.has("checked");
        fields.push(Field {
            tag: kind,
            kind: t
                .attr("type")
                .map_or_else(|| default.to_owned(), |ty| ty.to_ascii_lowercase()),
            name: name.into_owned(),
            value: if checkbox_off {
                String::new()
            } else {
                t.attr("value").map_or_default(Cow::into_owned)
            },
        });
    }
    (fields, closes)
}

/// The sign-in form posting to `action` with `fields` (which carry `auth`, `password` and
/// `csrfKey`), or what keeps it from being submitted: a visible field this client would not
/// fill, or no submit button.
fn complete_form(
    action: String,
    fields: &[Field],
    anonymous: bool,
) -> Result<LoginForm, FormProblem> {
    if let Some(f) = fields.iter().find(|f| {
        f.name != AUTH
            && f.name != PASSWORD
            && (matches!(f.tag, "select" | "textarea")
                || matches!(
                    f.kind.as_str(),
                    "text" | "password" | "email" | "number" | "tel" | "url" | "search"
                ))
    }) {
        return Err(FormProblem::UnknownField(f.name.chars().take(32).collect()));
    }
    let submits = || {
        fields
            .iter()
            .filter(|f| f.name == SUBMIT && f.kind == "submit")
    };
    let submit = submits()
        .find(|f| f.value == PASSWORD_HANDLER)
        .or_else(|| submits().next());
    let Some(s) = submit else {
        return Err(FormProblem::Missing("_processLogin"));
    };
    Ok(LoginForm {
        action,
        hidden: fields
            .iter()
            .filter(|f| f.kind == "hidden")
            .map(|f| (f.name.clone(), f.value.clone()))
            .collect(),
        submit: (s.name.clone(), s.value.clone()),
        anonymous,
    })
}

impl LoginForm {
    /// The body a browser posts for this form with `username` and `password`: the hidden
    /// fields in page order, the account name and password, "Sign in anonymously" when the form
    /// offers it, and the submit button. "Remember me" stays unchecked: no long-lived sign-in key
    /// is created for a session that lives only in memory.
    pub(super) fn body(&self, username: &str, password: &str) -> Zeroizing<Vec<u8>> {
        let mut fields: Vec<(&str, &str)> = self
            .hidden
            .iter()
            .filter(|(n, _)| n != REMEMBER_ME && n != ANONYMOUS)
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        fields.push((AUTH, username));
        fields.push((PASSWORD, password));
        if self.anonymous {
            fields.push((ANONYMOUS, "1"));
        }
        fields.push((self.submit.0.as_str(), self.submit.1.as_str()));
        form_body(&fields)
    }
}

/// `application/x-www-form-urlencoded` as browsers write it: `*-._` and alphanumerics as they
/// are, space as `+`, every other byte `%XX`.
pub(super) fn form_body(fields: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
    let len: usize = fields
        .iter()
        .map(|(n, v)| 3 * (n.len() + v.len()) + 2)
        .sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for (i, (name, value)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        for (part, last) in [(name, false), (value, true)] {
            for &byte in part.as_bytes() {
                match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                        out.push(byte);
                    }
                    b' ' => out.push(b'+'),
                    _ => {
                        const HEX: &[u8; 16] = b"0123456789ABCDEF";
                        out.extend_from_slice(&[
                            b'%',
                            HEX[usize::from(byte >> 4)],
                            HEX[usize::from(byte & 0xf)],
                        ]);
                    }
                }
            }
            if !last {
                out.push(b'=');
            }
        }
    }
    out
}

// -------------------------------------------------------------------------------------------
// The Ports page
// -------------------------------------------------------------------------------------------

/// What the Ports page's `air_data` element says about the page token (`ecsrf`).
#[derive(Debug)]
pub(super) enum Token {
    /// A 64-hex token.
    Found(Zeroizing<String>),
    /// `air_data` is there without a token: a signed-out page.
    Absent,
    /// A token that is not 64 hex digits.
    Malformed,
    /// No `air_data` element with readable JSON.
    NoElement,
}

/// The `ecsrf` of the element `id="air_data"`'s `data-json` (HTML-escaped JSON).
pub(super) fn token(page: &str) -> Token {
    #[derive(serde::Deserialize)]
    struct Data<'a> {
        #[serde(borrow, default)]
        ecsrf: Option<&'a str>,
    }
    let Some(raw) = tags(page)
        .into_iter()
        .find(|t| !t.end && t.attr("id").is_some_and(|id| id == "air_data"))
        .and_then(|t| t.raw("data-json"))
    else {
        return Token::NoElement;
    };
    let mut json = Zeroizing::new(String::with_capacity(raw.len()));
    decode_into(raw, &mut json);
    let Ok(data) = serde_json::from_str::<Data<'_>>(&json) else {
        return Token::NoElement;
    };
    match data.ecsrf {
        None => Token::Absent,
        Some(t) if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Token::Found(Zeroizing::new(t.to_owned()))
        }
        Some(_) => Token::Malformed,
    }
}

// -------------------------------------------------------------------------------------------
// What a page says
// -------------------------------------------------------------------------------------------

fn has_any(text: &str, words: &[&str]) -> bool {
    let lower = Zeroizing::new(text.to_ascii_lowercase());
    words.iter().any(|w| lower.contains(w))
}

/// The page carries a sign-in form (a signed-out page, or the form again after a refusal).
pub(super) fn has_login_form(page: &str) -> bool {
    !matches!(
        login_form(page),
        Err(FormProblem::NoForm | FormProblem::Missing(_))
    )
}

pub(super) fn captcha(page: &str) -> bool {
    has_any(page, CAPTCHA)
}

/// The page asks for a second sign-in step (a code, an authenticator, a security question).
pub(super) fn second_factor(page: &str) -> bool {
    if has_any(page, SECOND_FACTOR) {
        return true;
    }
    tags(page).iter().any(|t| {
        !t.end
            && (t.is("input") || t.is("form"))
            && ["name", "id", "data-controller"].iter().any(|a| {
                t.attr(a).is_some_and(|v| {
                    let v = v.to_ascii_lowercase();
                    SECOND_FACTOR_FIELDS.iter().any(|w| v.contains(w))
                })
            })
    })
}

/// The answer says the session is signed out (or its page token went stale).
pub(super) fn signed_out(text: &str) -> bool {
    has_any(text, SIGNED_OUT) || has_any(text, STALE_TOKEN)
}

/// The sign-in was refused for too many attempts.
pub(super) fn locked(text: &str) -> bool {
    has_any(text, LOCKED)
}

/// The text of the page's first error message (IPS `ipsMessage_error`, `AirVPN`'s
/// `message_error`), tags dropped and white space collapsed.
pub(super) fn message(page: &str) -> Option<String> {
    let tags = tags(page);
    let at = tags.iter().position(|t| {
        !t.end && (t.has_class("ipsMessage_error") || t.has_class("message_error"))
    })?;
    let open = &tags[at];
    let mut depth = 0usize;
    let mut stop = page.len();
    for t in &tags[at + 1..] {
        if !t.name.eq_ignore_ascii_case(open.name) {
            continue;
        }
        if !t.end {
            depth += 1;
        } else if depth == 0 {
            stop = t.span.start;
            break;
        } else {
            depth -= 1;
        }
    }
    let text: String = fragment_text(&page[open.span.end..stop.max(open.span.end)])
        .chars()
        .take(MAX_MESSAGE)
        .collect();
    (!text.is_empty()).then_some(text)
}

/// The text of an HTML fragment (a page element, an XHR answer's message): tags dropped,
/// entities decoded, white space collapsed.
pub(super) fn fragment_text(fragment: &str) -> String {
    let mut text = String::with_capacity(fragment.len());
    let mut rest = fragment;
    while let Some(lt) = rest.find('<') {
        text.push_str(&rest[..lt]);
        text.push(' ');
        rest = rest[lt..].find('>').map_or("", |gt| &rest[lt + gt + 1..]);
    }
    text.push_str(rest);
    decode(&text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `text` when it is a short plain sentence that names nothing secret: [`plain`] within 160
/// characters, with at least one letter. Otherwise `None`: a message from the provider reaches
/// the user only in this form.
pub(super) fn readable(text: &str, secrets: &[&str]) -> Option<String> {
    plain(text, 160, secrets).filter(|t| t.chars().any(char::is_alphabetic))
}

/// `text` when it is plain and names nothing secret: at most `max` characters, no markup or JSON
/// punctuation, no `@` (an e-mail address), no run of 20 letters or digits (a token, a key, a
/// cookie), and none of `secrets` (ignoring case). Digits alone pass (a list of ports).
pub(super) fn plain(text: &str, max: usize, secrets: &[&str]) -> Option<String> {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars = text.chars().count();
    if !(1..=max).contains(&chars)
        || text.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '<' | '>' | '{' | '}' | '[' | ']' | '=' | '&' | '@' | '\\'
                )
        })
    {
        return None;
    }
    let mut run = 0;
    for c in text.chars() {
        run = if c.is_ascii_alphanumeric() {
            run + 1
        } else {
            0
        };
        if run >= 20 {
            return None;
        }
    }
    let lower = text.to_lowercase();
    if secrets
        .iter()
        .filter(|s| s.len() >= 3)
        .any(|s| lower.contains(&s.to_lowercase()))
    {
        return None;
    }
    Some(text)
}

/// A short, scrubbed view of an answer for the debug log: an HTML page's title and first error
/// message, else the start of the text. Control characters become spaces, `secrets` (ignoring
/// case) and every run of 16 or more token-like characters become `…`.
pub(super) fn snippet(body: &[u8], secrets: &[&str]) -> String {
    let text =
        Zeroizing::new(String::from_utf8_lossy(&body[..body.len().min(256 * 1024)]).into_owned());
    let view = if text.trim_start().starts_with('<') {
        let title = tags(&text)
            .iter()
            .position(|t| !t.end && t.is("title"))
            .and_then(|at| {
                let from = tags(&text)[at].span.end;
                find_ci(text.as_bytes(), from, b"</title")
                    .map(|to| decode(&text[from..to]).into_owned())
            })
            .unwrap_or_default();
        format!(
            "html title={:?} message={:?}",
            title.trim(),
            message(&text).unwrap_or_default()
        )
    } else {
        text.chars().take(4 * SNIPPET).collect()
    };
    let mut view: String = view
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    for secret in secrets.iter().filter(|s| s.len() >= 3) {
        view = replace_ci(&view, secret, "…");
    }
    let mut out = String::with_capacity(view.len());
    let mut run = String::new();
    let token_like =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-' | '%');
    for c in view.chars().chain(std::iter::once(' ')) {
        if token_like(c) {
            run.push(c);
            continue;
        }
        if run.chars().count() >= 16 {
            out.push('…');
        } else {
            out.push_str(&run);
        }
        run.clear();
        out.push(c);
    }
    out.pop();
    out.chars().take(SNIPPET).collect()
}

/// `text` with every `needle` (ignoring case) replaced.
fn replace_ci(text: &str, needle: &str, with: &str) -> String {
    let lower = text.to_lowercase();
    let needle = needle.to_lowercase();
    if needle.is_empty() || lower.len() != text.len() || !lower.contains(&needle) {
        // Case folding changed the length (rare scripts): drop the text rather than risk it.
        return if lower.contains(&needle) {
            "…".into()
        } else {
            text.into()
        };
    }
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while let Some(at) = lower[from..].find(&needle) {
        out.push_str(&text[from..from + at]);
        out.push_str(with);
        from += at + needle.len();
    }
    out.push_str(&text[from..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    /// The sign-in form of `https://airvpn.org/login/` as served to a signed-out client on
    /// 2026-11-02 (the `csrfKey` value replaced).
    const LOGIN_PAGE: &str = include_str!("../../../tests/fixtures/airvpn/site/login.html");
    /// `https://airvpn.org/ports/` as served to a signed-out client on 2026-11-02: the header's
    /// sign-in form, "Login required." and `air_data` without a token.
    const PORTS_SIGNED_OUT: &str =
        include_str!("../../../tests/fixtures/airvpn/site/ports-signed-out.html");

    #[test]
    fn a_changed_form_is_named_and_a_captcha_is_seen_before_posting() {
        let without_csrf = LOGIN_PAGE.replace("name=\"csrfKey\"", "name=\"csrf\"");
        assert_eq!(
            login_form(&without_csrf).unwrap_err(),
            FormProblem::Missing("csrfKey")
        );
        let renamed = LOGIN_PAGE.replace("name=\"auth\"", "name=\"login\"");
        assert_matches!(
            login_form(&renamed).unwrap_err(),
            FormProblem::Missing("auth") | FormProblem::UnknownField(_)
        );
        let extra = LOGIN_PAGE.replace(
            "<input type=\"password\"",
            "<input type=\"text\" name=\"otp_code\"><input type=\"password\"",
        );
        assert_eq!(
            login_form(&extra).unwrap_err(),
            FormProblem::UnknownField("otp_code".into())
        );
        let captcha = LOGIN_PAGE.replace(
            "<button type=\"submit\" name=\"_processLogin\"",
            "<div class=\"g-recaptcha\" data-sitekey=\"x\"></div><button type=\"submit\" name=\"_processLogin\"",
        );
        assert_eq!(login_form(&captcha).unwrap_err(), FormProblem::Captcha);
        assert_eq!(
            login_form("<html><body>maintenance</body></html>").unwrap_err(),
            FormProblem::NoForm
        );
        let no_submit = LOGIN_PAGE.replace("name=\"_processLogin\"", "name=\"go\"");
        assert_eq!(
            login_form(&no_submit).unwrap_err(),
            FormProblem::Missing("_processLogin")
        );
    }

    #[test]
    fn only_a_short_plain_sentence_without_secrets_is_readable() {
        assert_eq!(
            readable(
                "  The password you entered is   incorrect. ",
                &["exampleuser"]
            )
            .as_deref(),
            Some("The password you entered is incorrect.")
        );
        assert_eq!(
            readable("Hello ExampleUser, wrong password", &["exampleuser"]),
            None
        );
        assert_eq!(readable("mail me at a@b.example", &[]), None);
        assert_eq!(
            readable("token 0123456789abcdef0123456789abcdef invalid", &[]),
            None
        );
        assert_eq!(readable("<b>bold</b>", &[]), None);
        assert_eq!(readable("{\"error\":1}", &[]), None);
        assert_eq!(readable(&"word ".repeat(40), &[]), None);
        assert_eq!(readable("12345", &[]), None);
        // A list of ports is plain, within its own limit.
        assert_eq!(
            plain("41000, 41001", 40, &[]).as_deref(),
            Some("41000, 41001")
        );
        assert_eq!(plain(&"41000 ".repeat(10), 40, &[]), None);
        assert_eq!(plain("x=1", 40, &[]), None);
    }

    #[test]
    fn a_snippet_hides_secrets_and_token_like_runs() {
        let hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let body = format!(
            "{{\"ecsrf\":\"{hex}\",\"user\":\"ExampleUser\",\"cookie\":\"PHPSESSID=0a1b2c3d4e5f6g7h8i9j0k1l2m\",\n\"pw\":\"hunter2\"}}"
        );
        let s = snippet(body.as_bytes(), &["exampleuser", "hunter2"]);
        for secret in [hex, "ExampleUser", "0a1b2c3d4e5f6g7h8i9j0k1l2m", "hunter2"] {
            assert!(!s.contains(secret), "{s}");
        }
        assert!(!s.contains('\n'));
        assert!(s.chars().count() <= SNIPPET);
        let page = snippet(PORTS_SIGNED_OUT.as_bytes(), &[]);
        assert!(page.contains("Login required."), "{page}");
        assert!(
            !page.contains("aHR0cHM6Ly9haXJ2cG4ub3JnL3BvcnRzLw"),
            "{page}"
        );
    }
}
