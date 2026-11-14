//! Names and paths (pure).
//!
//! Which entries of the source folder a job takes, the local name of a
//! finished file (unique, shortened when too long — the original tool's rules), and where a
//! partial download resumes.

use vpn_domain::{SshDownloadNameFilter, remote_path};

/// Longest local file name written (the original tool's `OTHER_CONFIG_MAX_FILENAME_BYTES`):
/// room under the usual 255-byte limit.
pub const MAX_NAME_BYTES: usize = 240;
/// An extension longer than this is kept as part of the name when it is shortened.
const MAX_EXTENSION_BYTES: usize = 32;

/// Why a source entry is left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Not a regular file (folder, link, device…).
    NotFile,
    /// Starts with `.` and the job skips those.
    Hidden,
    /// Left out by the job's name filter.
    Filtered,
    /// A name no local file can safely have: `.`/`..`, a `/`, control characters, or bytes that
    /// are not UTF-8 (the server's name cannot be sent back unchanged).
    Unusable,
}

/// Whether `s[at..]` starts with a canonical UUID (8-4-4-4-12 hex digits).
fn uuid_at(s: &[u8], at: usize) -> bool {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let mut i = at;
    for (n, len) in GROUPS.iter().enumerate() {
        if n > 0 {
            if s.get(i) != Some(&b'-') {
                return false;
            }
            i += 1;
        }
        for _ in 0..*len {
            match s.get(i) {
                Some(c) if c.is_ascii_hexdigit() => i += 1,
                _ => return false,
            }
        }
    }
    true
}

/// Whether any part of `name` is a UUID (the original tool's unanchored match).
#[must_use]
pub fn contains_uuid(name: &str) -> bool {
    let b = name.as_bytes();
    (0..b.len()).any(|i| uuid_at(b, i))
}

/// Whether a job takes the entry `name` of its source folder (a regular file).
///
/// # Errors
///
/// [`Skip::Unusable`] for a name no local file can safely have, [`Skip::Hidden`] for a hidden
/// name the job skips, and [`Skip::Filtered`] for a name the job's UUID filter leaves out.
pub fn take_name(name: &str, filter: SshDownloadNameFilter, skip_hidden: bool) -> Result<(), Skip> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\u{fffd}')
        || name.chars().any(char::is_control)
    {
        return Err(Skip::Unusable);
    }
    if skip_hidden && name.starts_with('.') {
        return Err(Skip::Hidden);
    }
    let uuid = contains_uuid(name);
    match filter {
        SshDownloadNameFilter::SkipUuid if uuid => Err(Skip::Filtered),
        SshDownloadNameFilter::OnlyUuid if !uuid => Err(Skip::Filtered),
        _ => Ok(()),
    }
}

fn split_extension(name: &str) -> (&str, Option<&str>) {
    match name.rsplit_once('.') {
        Some((stem, ext))
            if !stem.is_empty() && !ext.is_empty() && ext.len() <= MAX_EXTENSION_BYTES =>
        {
            (stem, Some(ext))
        }
        _ => (name, None),
    }
}

/// `value` cut to at most `max` bytes, at a character boundary.
fn truncate_utf8(value: &str, max: usize) -> &str {
    // A character boundary at or below `max` (all of `value` when it fits), so `get` always has
    // the prefix.
    value
        .get(..value.floor_char_boundary(max))
        .unwrap_or_default()
}

/// `original` as a local name of at most `max_bytes`.
///
/// Unchanged when it fits (and no suffix is
/// forced), else `<stem cut short>--<suffix>.<ext>` — the extension is kept, so the file still
/// opens with the same program. The suffix (the record's id) makes the name unique.
pub fn safe_name_with_suffix(
    original: &str,
    max_bytes: usize,
    suffix: &str,
    force_suffix: bool,
) -> String {
    if !force_suffix && original.len() <= max_bytes {
        return original.to_string();
    }
    let (stem, ext) = split_extension(original);
    let suffix = format!("--{suffix}");
    let ext = ext.map_or_else(String::new, |e| format!(".{e}"));
    let room = max_bytes.saturating_sub(suffix.len() + ext.len());
    let stem = truncate_utf8(stem, room);
    let stem = if stem.is_empty() {
        truncate_utf8(suffix.trim_start_matches('-'), room)
    } else {
        stem
    };
    let name = format!("{stem}{suffix}{ext}");
    // A suffix that does not fit at all (an absurd limit): the record id alone.
    if name.len() > max_bytes {
        return truncate_utf8(suffix.trim_start_matches('-'), max_bytes).to_string();
    }
    name
}

/// The local name a finished file gets first: its own name when it fits, else a shortened one
/// carrying `id`. `true` when it had to be shortened.
#[must_use]
pub fn local_name(original: &str, id: &str) -> (String, bool) {
    if original.len() <= MAX_NAME_BYTES {
        (original.to_string(), false)
    } else {
        (
            safe_name_with_suffix(original, MAX_NAME_BYTES, id, true),
            true,
        )
    }
}

/// The name a file gets when its own is taken (locally, or in the remote failed folder).
#[must_use]
pub fn unique_name(original: &str, id: &str) -> String {
    safe_name_with_suffix(original, MAX_NAME_BYTES, id, true)
}

/// `dir/name` on the server (`~/` paths are relative to the login folder).
#[must_use]
pub fn join_remote(dir: &str, name: &str) -> String {
    match remote_path(dir) {
        "" | "." => name.to_string(),
        "/" => format!("/{name}"),
        d => format!("{d}/{name}"),
    }
}

/// How a partial download continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePlan {
    /// The next byte to fetch.
    pub offset: u64,
    /// The local file is longer than the remote one: start over.
    pub truncate_local: bool,
    pub complete: bool,
}

/// The original tool's resume rule.
///
/// A shorter local file continues at its length, an equal one
/// is complete, a longer one (the remote file was replaced) starts over; an empty remote file is
/// complete at once.
#[must_use]
pub fn plan_resume(local: u64, remote: u64) -> ResumePlan {
    if remote == 0 {
        return ResumePlan {
            offset: 0,
            truncate_local: local > 0,
            complete: true,
        };
    }
    match local.cmp(&remote) {
        std::cmp::Ordering::Equal => ResumePlan {
            offset: local,
            truncate_local: false,
            complete: true,
        },
        std::cmp::Ordering::Less => ResumePlan {
            offset: local,
            truncate_local: false,
            complete: false,
        },
        std::cmp::Ordering::Greater => ResumePlan {
            offset: 0,
            truncate_local: true,
            complete: false,
        },
    }
}

/// `~/x` under `home`; other paths unchanged.
#[must_use]
pub fn expand_home(path: &str, home: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    path.strip_prefix("~/").map_or_else(
        || Some(std::path::PathBuf::from(path)),
        |rest| home.map(|h| h.join(rest)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "3f2b8c1e-9a4d-4e7b-8c21-5d6f7a8b9c0d";

    #[test]
    fn names_are_taken_by_the_filter_and_unusable_ones_never() {
        use SshDownloadNameFilter::*;
        let uuid = format!("{ID}.mkv");
        assert_eq!(take_name("movie.mkv", All, true), Ok(()));
        assert_eq!(take_name(&uuid, All, true), Ok(()));
        assert_eq!(take_name(&uuid, SkipUuid, true), Err(Skip::Filtered));
        assert_eq!(take_name("movie.mkv", SkipUuid, true), Ok(()));
        assert_eq!(take_name("movie.mkv", OnlyUuid, true), Err(Skip::Filtered));
        assert_eq!(take_name(&uuid, OnlyUuid, true), Ok(()));
        assert_eq!(take_name(".movie.mkv.part", All, true), Err(Skip::Hidden));
        assert_eq!(take_name(".movie.mkv.part", All, false), Ok(()));
        for bad in [
            ".",
            "..",
            "",
            "a/b",
            "line\nbreak",
            "bell\u{7}",
            "lossy\u{fffd}",
        ] {
            assert_eq!(take_name(bad, All, false), Err(Skip::Unusable), "{bad:?}");
        }
        assert_eq!(take_name("中文 檔名.txt", All, true), Ok(()));
    }
}
