//! Naming things on the command line: a full id, a unique name, or a unique id prefix (at least
//! four characters). Anything ambiguous or unknown is a usage error that lists what exists.

use crate::cmd::Failure;

/// Shortest id prefix accepted.
const PREFIX_MIN: usize = 4;
/// Candidates listed in an error.
const LIST_MAX: usize = 10;

/// Pick the one item `query` names. `what` names the kind of thing in messages.
pub fn pick<'a, T>(
    items: &'a [T],
    query: &str,
    what: &str,
    id: impl Fn(&T) -> String,
    name: impl Fn(&T) -> String,
) -> Result<&'a T, Failure> {
    let q = query.trim();
    if q.is_empty() {
        return Err(Failure::Usage(format!("請指定{what}（名稱或 ID）")));
    }
    let lower = q.to_lowercase();
    if let Some(found) = items.iter().find(|t| id(t).to_lowercase() == lower) {
        return Ok(found);
    }
    let named: Vec<&T> = items.iter().filter(|t| name(t) == q).collect();
    match named.len() {
        1 => return Ok(named[0]),
        0 => {}
        _ => {
            return Err(Failure::Usage(format!(
                "有 {} 個{what}叫「{q}」，請改用 ID：\n{}",
                named.len(),
                listing(&named, &id, &name)
            )));
        }
    }
    if q.len() >= PREFIX_MIN {
        let prefixed: Vec<&T> = items
            .iter()
            .filter(|t| id(t).to_lowercase().starts_with(&lower))
            .collect();
        match prefixed.len() {
            1 => return Ok(prefixed[0]),
            0 => {}
            _ => {
                return Err(Failure::Usage(format!(
                    "「{q}」符合 {} 個{what}的 ID，請多打幾個字：\n{}",
                    prefixed.len(),
                    listing(&prefixed, &id, &name)
                )));
            }
        }
    }
    let all: Vec<&T> = items.iter().collect();
    Err(Failure::Usage(if all.is_empty() {
        format!("找不到{what}「{q}」（目前沒有任何{what}）")
    } else {
        format!(
            "找不到{what}「{q}」。現有的{what}：\n{}",
            listing(&all, &id, &name)
        )
    }))
}

fn listing<T>(items: &[&T], id: &impl Fn(&T) -> String, name: &impl Fn(&T) -> String) -> String {
    let mut lines: Vec<String> = items
        .iter()
        .take(LIST_MAX)
        .map(|t| format!("  {}  {}", id(t), name(t)))
        .collect();
    if items.len() > LIST_MAX {
        lines.push(format!("  …另外 {} 個", items.len() - LIST_MAX));
    }
    lines.join("\n")
}
