// SPDX-License-Identifier: GPL-3.0-or-later

//! The website session's cookies (RFC 6265, the part a single host needs): kept in memory,
//! sent only to airvpn.org, never printed. A cookie for another domain is refused; one that
//! expires (`Max-Age` ≤ 0, an `Expires` date passed) is removed. Paths are not tracked: every
//! cookie the site sets is for `/`.

use http::header::{HeaderMap, HeaderValue, SET_COOKIE};
use time::format_description::StaticFormatDescription;
use time::{OffsetDateTime, PrimitiveDateTime};
use zeroize::Zeroizing;

/// More than the site sets (it sets four or five).
const MAX_COOKIES: usize = 32;
const MAX_NAME: usize = 128;
const MAX_VALUE: usize = 4096;
/// The one domain these cookies belong to.
const DOMAIN: &str = "airvpn.org";

/// RFC 9110 IMF-fixdate.
const IMF_FIXDATE: StaticFormatDescription = time::macros::format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);
/// The dashed form PHP writes (`Wed, 02-Dec-2026 10:00:41 GMT`).
const DASHED: StaticFormatDescription = time::macros::format_description!(
    "[weekday repr:short], [day]-[month repr:short]-[year] [hour]:[minute]:[second] GMT"
);

struct Cookie {
    name: String,
    value: Zeroizing<String>,
}

#[derive(Default)]
pub(super) struct Jar {
    cookies: Vec<Cookie>,
}

impl Jar {
    /// Take the `Set-Cookie` headers of an answer.
    pub(super) fn store(&mut self, headers: &HeaderMap, now: OffsetDateTime) {
        for value in headers.get_all(SET_COOKIE) {
            if let Ok(line) = value.to_str() {
                self.set(line, now);
            }
        }
    }

    fn set(&mut self, line: &str, now: OffsetDateTime) {
        let mut parts = line.split(';');
        let Some((name, value)) = parts.next().and_then(|p| p.split_once('=')) else {
            return;
        };
        let (name, value) = (name.trim(), value.trim());
        if !valid_name(name) || !valid_value(value) {
            return;
        }
        let mut max_age = None;
        let mut expires = None;
        for attribute in parts {
            let (key, val) = attribute.split_once('=').unwrap_or((attribute, ""));
            let val = val.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "max-age" => max_age = val.parse::<i64>().ok(),
                "expires" => expires = expiry(val),
                "domain" => {
                    let domain = val.trim_start_matches('.').to_ascii_lowercase();
                    if !domain.is_empty() && domain != DOMAIN {
                        return;
                    }
                }
                _ => {}
            }
        }
        // Max-Age wins over Expires (RFC 6265 §5.3 step 3).
        let stale = max_age.map_or_else(
            || expires.is_some_and(|at| at <= now),
            |seconds| seconds <= 0,
        );
        self.cookies.retain(|c| c.name != name);
        if !stale && self.cookies.len() < MAX_COOKIES {
            self.cookies.push(Cookie {
                name: name.to_owned(),
                value: Zeroizing::new(value.to_owned()),
            });
        }
    }

    /// The `Cookie` header to send (marked sensitive), or `None` while the jar is empty.
    pub(super) fn header(&self) -> Option<HeaderValue> {
        if self.cookies.is_empty() {
            return None;
        }
        let mut line = Zeroizing::new(String::new());
        for (i, c) in self.cookies.iter().enumerate() {
            if i > 0 {
                line.push_str("; ");
            }
            line.push_str(&c.name);
            line.push('=');
            line.push_str(&c.value);
        }
        let mut value = HeaderValue::from_str(&line).ok()?;
        value.set_sensitive(true);
        Some(value)
    }

    /// The values held, to keep them out of anything logged.
    pub(super) fn values(&self) -> impl Iterator<Item = &str> {
        self.cookies.iter().map(|c| c.value.as_str())
    }

    pub(super) const fn len(&self) -> usize {
        self.cookies.len()
    }

    #[cfg(test)]
    fn get(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.value.as_str())
    }
}

/// A cookie name is an RFC 9110 token.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.bytes().all(|b| {
            b.is_ascii_graphic()
                && !matches!(
                    b,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
}

/// RFC 6265 cookie-octets, optionally in double quotes.
fn valid_value(value: &str) -> bool {
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    value.len() <= MAX_VALUE
        && inner
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b',' | b';' | b'\\'))
}

fn expiry(value: &str) -> Option<OffsetDateTime> {
    [IMF_FIXDATE, DASHED]
        .iter()
        .find_map(|f| PrimitiveDateTime::parse(value, f).ok())
        .map(PrimitiveDateTime::assume_utc)
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn headers(lines: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for l in lines {
            h.append(SET_COOKIE, HeaderValue::from_str(l).unwrap());
        }
        h
    }

    const NOW: OffsetDateTime = datetime!(2026-11-02 10:00:00 UTC);

    #[test]
    fn expired_foreign_and_malformed_cookies_are_not_kept() {
        let mut jar = Jar::default();
        jar.store(
            &headers(&["a=1; path=/", "b=2; path=/", "c=3; path=/"]),
            NOW,
        );
        jar.store(
            &headers(&[
                // PHP's deletion: both a past date and Max-Age=0.
                "a=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/",
                // A past IMF date alone.
                "b=gone; expires=Sun, 01 Nov 2026 10:00:00 GMT",
                // Max-Age wins over a date in the past.
                "c=kept; expires=Sun, 01 Nov 2026 10:00:00 GMT; Max-Age=60",
                "d=1; Domain=evil.example",
                "e=1; Domain=.airvpn.org",
                "f=1; Domain=www.airvpn.org",
                "=nameless",
                "g=bad value",
                "h=\"quoted\"",
            ]),
            NOW,
        );
        assert_eq!(jar.get("a"), None);
        assert_eq!(jar.get("b"), None);
        assert_eq!(jar.get("c"), Some("kept"));
        assert_eq!(jar.get("d"), None);
        assert_eq!(jar.get("e"), Some("1"));
        assert_eq!(jar.get("f"), None);
        assert_eq!(jar.get("g"), None);
        assert_eq!(jar.get("h"), Some("\"quoted\""));
        assert!(Jar::default().header().is_none());
    }
}
