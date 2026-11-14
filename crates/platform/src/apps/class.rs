//! What kind of program an App's executable is, for starting it as a process of its own.
//!
//! [`AppClass`] tells apart browsers that a data directory of their own makes a separate instance,
//! macOS apps that cannot be made one, and launchers whose job is to have something else started.
//!
//! - macOS: a bundle — the `.app` itself or its main executable (`CFBundleExecutable`) —
//!   by its `CFBundleIdentifier`. Every bundle that is not a known browser is a [`AppClass::Gui`]
//!   app. Another file inside `Contents/MacOS` (a command-line tool shipped in the bundle) is not
//!   the app.
//! - Otherwise by file name: the resolved file's, then the typed path's (`/snap/bin/firefox`
//!   resolves to `snap`).
//!
//! And the other side of a start that ended at once: processes outside the App's tree that run
//! the same program ([`same_program_elsewhere`]), where such a start may have handed over to.

use std::path::{Path, PathBuf};

use vpn_domain::{AppClass, AppClassInfo, ExecutableKind};

use super::proc::{ProcInfo, ProcTable, Tree};

use AppClass::{Chromium, Firefox, Gui, Launcher};

/// Known macOS bundle identifiers (compared case-insensitively, as `LaunchServices` does).
const BUNDLES: &[(&str, &str, AppClass)] = &[
    ("com.google.Chrome", "Google Chrome", Chromium),
    ("com.google.Chrome.beta", "Google Chrome Beta", Chromium),
    ("com.google.Chrome.dev", "Google Chrome Dev", Chromium),
    ("com.google.Chrome.canary", "Google Chrome Canary", Chromium),
    ("org.chromium.Chromium", "Chromium", Chromium),
    ("com.microsoft.edgemac", "Microsoft Edge", Chromium),
    (
        "com.microsoft.edgemac.Beta",
        "Microsoft Edge Beta",
        Chromium,
    ),
    ("com.microsoft.edgemac.Dev", "Microsoft Edge Dev", Chromium),
    (
        "com.microsoft.edgemac.Canary",
        "Microsoft Edge Canary",
        Chromium,
    ),
    ("com.brave.Browser", "Brave", Chromium),
    ("com.brave.Browser.beta", "Brave Beta", Chromium),
    ("com.brave.Browser.nightly", "Brave Nightly", Chromium),
    ("company.thebrowser.Browser", "Arc", Chromium),
    ("com.vivaldi.Vivaldi", "Vivaldi", Chromium),
    ("com.operasoftware.Opera", "Opera", Chromium),
    ("com.operasoftware.OperaGX", "Opera GX", Chromium),
    ("org.mozilla.firefox", "Firefox", Firefox),
    (
        "org.mozilla.firefoxdeveloperedition",
        "Firefox Developer Edition",
        Firefox,
    ),
    ("org.mozilla.nightly", "Firefox Nightly", Firefox),
    ("org.mozilla.librewolf", "LibreWolf", Firefox),
    ("io.gitlab.librewolf-community", "LibreWolf", Firefox),
    ("net.waterfox.waterfox", "Waterfox", Firefox),
    ("app.zen-browser.zen", "Zen", Firefox),
    ("one.ablaze.floorp", "Floorp", Firefox),
    ("com.apple.Safari", "Safari", Gui),
    (
        "com.apple.SafariTechnologyPreview",
        "Safari Technology Preview",
        Gui,
    ),
];

/// Known file names (Linux packages, and wrappers anywhere).
const NAMES: &[(&str, &str, AppClass)] = &[
    ("chrome", "Google Chrome", Chromium),
    ("google-chrome", "Google Chrome", Chromium),
    ("google-chrome-stable", "Google Chrome", Chromium),
    ("google-chrome-beta", "Google Chrome Beta", Chromium),
    ("google-chrome-unstable", "Google Chrome Dev", Chromium),
    ("chromium", "Chromium", Chromium),
    ("chromium-browser", "Chromium", Chromium),
    ("microsoft-edge", "Microsoft Edge", Chromium),
    ("microsoft-edge-stable", "Microsoft Edge", Chromium),
    ("microsoft-edge-beta", "Microsoft Edge Beta", Chromium),
    ("microsoft-edge-dev", "Microsoft Edge Dev", Chromium),
    ("msedge", "Microsoft Edge", Chromium),
    ("brave", "Brave", Chromium),
    ("brave-browser", "Brave", Chromium),
    ("brave-browser-stable", "Brave", Chromium),
    ("brave-browser-beta", "Brave Beta", Chromium),
    ("brave-browser-nightly", "Brave Nightly", Chromium),
    ("vivaldi", "Vivaldi", Chromium),
    ("vivaldi-stable", "Vivaldi", Chromium),
    ("vivaldi-bin", "Vivaldi", Chromium),
    ("opera", "Opera", Chromium),
    ("firefox", "Firefox", Firefox),
    ("firefox-bin", "Firefox", Firefox),
    ("firefox-esr", "Firefox ESR", Firefox),
    (
        "firefox-developer-edition",
        "Firefox Developer Edition",
        Firefox,
    ),
    ("firefox-nightly", "Firefox Nightly", Firefox),
    ("librewolf", "LibreWolf", Firefox),
    ("waterfox", "Waterfox", Firefox),
    ("floorp", "Floorp", Firefox),
    // Programs that have something else started; the alternatives names when they do not
    // resolve to a known browser.
    ("xdg-open", "xdg-open", Launcher),
    ("gnome-open", "gnome-open", Launcher),
    ("kde-open", "kde-open", Launcher),
    ("kde-open5", "kde-open5", Launcher),
    ("kde-open6", "kde-open6", Launcher),
    ("exo-open", "exo-open", Launcher),
    ("gtk-launch", "gtk-launch", Launcher),
    ("sensible-browser", "sensible-browser", Launcher),
    ("x-www-browser", "x-www-browser", Launcher),
    ("www-browser", "www-browser", Launcher),
];

/// macOS's `LaunchServices` client: what it opens is started by launchd, never its child.
const MACOS_OPEN: &str = "/usr/bin/open";

fn info(class: AppClass, name: &str, bundle_id: Option<String>) -> AppClassInfo {
    AppClassInfo {
        class,
        name: name.into(),
        bundle_id,
    }
}

/// A bundle identifier's class, when it is a known one.
#[must_use]
pub fn by_bundle_id(id: &str) -> Option<(AppClass, &'static str)> {
    BUNDLES
        .iter()
        .find(|(known, _, _)| known.eq_ignore_ascii_case(id))
        .map(|(_, name, class)| (*class, *name))
}

/// A file name's class, when it is a known one.
#[must_use]
pub fn by_name(file_name: &str) -> Option<(AppClass, &'static str)> {
    NAMES
        .iter()
        .find(|(known, _, _)| *known == file_name)
        .map(|(_, name, class)| (*class, *name))
}

/// What `path` (as typed) is, now that it resolved to `file` of `kind`. `None`: an ordinary
/// program.
#[must_use]
pub fn classify(path: &Path, file: &Path, kind: ExecutableKind) -> Option<AppClassInfo> {
    let bundle = match kind {
        ExecutableKind::AppBundle => path.canonicalize().ok(),
        ExecutableKind::File => bundle_of(file),
    };
    if let Some(bundle) = bundle
        && let Some(found) = bundle_class(&bundle)
    {
        return Some(found);
    }
    if cfg!(target_os = "macos") && file == Path::new(MACOS_OPEN) {
        return Some(info(Launcher, "open", None));
    }
    let name_of = |p: &Path| p.file_name().and_then(|n| n.to_str()).and_then(by_name);
    // The resolved file decides when it is a browser; the typed name catches a wrapper (snap) or
    // an alternatives name that resolved to something unknown.
    let found = match (name_of(file), name_of(path)) {
        (Some(f), _) if f.0 != Launcher => Some(f),
        (_, Some(p)) if p.0 != Launcher => Some(p),
        (f, p) => f.or(p),
    };
    found.map(|(class, name)| info(class, name, None))
}

/// The bundle whose main executable `file` is (macOS; `None` elsewhere, for a file that is not
/// in a bundle's `Contents/MacOS`, or another file of it).
#[must_use]
pub fn bundle_of(file: &Path) -> Option<PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let macos = file.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    let is_app = bundle
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("app"));
    if macos.file_name()? != "MacOS" || contents.file_name()? != "Contents" || !is_app {
        return None;
    }
    let main = main_executable(bundle)?;
    (file.file_name()? == main.as_str()).then(|| bundle.to_path_buf())
}

#[cfg(target_os = "macos")]
fn main_executable(bundle: &Path) -> Option<String> {
    super::executable::info_plist_string(bundle, "CFBundleExecutable")
        .ok()
        .flatten()
}

#[cfg(not(target_os = "macos"))]
const fn main_executable(_bundle: &Path) -> Option<String> {
    None
}

/// A bundle's class: a known browser, or a GUI app named by its bundle.
#[cfg(target_os = "macos")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as on the other systems, which know no bundle and answer `None`"
)]
fn bundle_class(bundle: &Path) -> Option<AppClassInfo> {
    use super::executable::info_plist_string;
    let id = info_plist_string(bundle, "CFBundleIdentifier")
        .ok()
        .flatten();
    if let Some((class, name)) = id.as_deref().and_then(by_bundle_id) {
        return Some(info(class, name, id));
    }
    let shown = ["CFBundleDisplayName", "CFBundleName"]
        .into_iter()
        .find_map(|k| info_plist_string(bundle, k).ok().flatten())
        .filter(|n| n.chars().count() <= 64 && !n.chars().any(char::is_control))
        .or_else(|| bundle.file_stem().map(|s| s.to_string_lossy().into_owned()))
        // A name, the same in every language: the bundle's path when it has no name at all.
        .unwrap_or_else(|| bundle.display().to_string());
    Some(info(Gui, &shown, id))
}

#[cfg(not(target_os = "macos"))]
const fn bundle_class(_bundle: &Path) -> Option<AppClassInfo> {
    None
}

/// The longest process name the OS reports (macOS keeps 32 bytes, Linux 15).
const NAME_LIMIT: usize = if cfg!(target_os = "linux") { 15 } else { 32 };

/// Whether a process runs `program`.
///
/// `exe` is the file the process runs and `name` what the OS calls it. It runs `program` when it is
/// the same file, a file of the same macOS bundle, or — for a script, which the OS shows by its
/// interpreter's file — the same name.
#[must_use]
pub fn runs_program(exe: Option<&Path>, name: &str, program: &Path, bundle: Option<&Path>) -> bool {
    if let Some(exe) = exe
        && (exe == program || bundle.is_some_and(|b| exe.starts_with(b)))
    {
        return true;
    }
    let Some(base) = program.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    // The OS cuts names at a byte limit, possibly inside a character.
    let shown = base
        .char_indices()
        .take_while(|(i, c)| i + c.len_utf8() <= NAME_LIMIT)
        .map(|(_, c)| c)
        .collect::<String>();
    !name.is_empty() && name == shown
}

/// A live process outside `tree` (and not this one) that runs `program` (or a file of `bundle`):
/// where a start that ended at once may have handed over to.
#[must_use]
pub fn same_program_elsewhere(
    table: &ProcTable,
    tree: &Tree,
    program: &Path,
    bundle: Option<&Path>,
) -> Option<ProcInfo> {
    let me = std::process::id();
    let mut found: Vec<&ProcInfo> = table
        .values()
        .filter(|p| !p.zombie && p.pid != me && !tree.contains_key(&p.pid))
        .filter(|p| {
            runs_program(
                super::proc::executable(p.pid).as_deref(),
                &p.name,
                program,
                bundle,
            )
        })
        .collect();
    // The longest-running one: the instance that was there first.
    found.sort_by_key(|p| (p.started_us, p.pid));
    found.first().map(|p| (*p).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browsers_and_apps_are_known_by_bundle_id() {
        for (id, class, name) in [
            ("com.google.Chrome", Chromium, "Google Chrome"),
            ("com.google.chrome", Chromium, "Google Chrome"),
            ("org.chromium.Chromium", Chromium, "Chromium"),
            ("com.microsoft.edgemac", Chromium, "Microsoft Edge"),
            ("com.brave.Browser", Chromium, "Brave"),
            ("company.thebrowser.Browser", Chromium, "Arc"),
            ("com.vivaldi.Vivaldi", Chromium, "Vivaldi"),
            ("org.mozilla.firefox", Firefox, "Firefox"),
            (
                "org.mozilla.firefoxdeveloperedition",
                Firefox,
                "Firefox Developer Edition",
            ),
            ("com.apple.Safari", Gui, "Safari"),
        ] {
            assert_eq!(by_bundle_id(id), Some((class, name)), "{id}");
        }
        assert_eq!(by_bundle_id("com.example.editor"), None);
    }

    #[test]
    fn browsers_and_launchers_are_known_by_file_name() {
        for (file, class) in [
            ("google-chrome", Chromium),
            ("google-chrome-stable", Chromium),
            ("chromium", Chromium),
            ("chromium-browser", Chromium),
            ("microsoft-edge", Chromium),
            ("brave-browser", Chromium),
            ("vivaldi", Chromium),
            ("firefox", Firefox),
            ("firefox-esr", Firefox),
            ("librewolf", Firefox),
            ("xdg-open", Launcher),
            ("x-www-browser", Launcher),
        ] {
            assert_eq!(by_name(file).map(|f| f.0), Some(class), "{file}");
        }
        for file in ["curl", "Firefox", "chrome.sh", "firefox.real", ""] {
            assert_eq!(by_name(file), None, "{file}");
        }
    }

    #[test]
    fn the_resolved_file_decides_and_the_typed_name_catches_wrappers() {
        let class = |typed: &str, file: &str| {
            classify(Path::new(typed), Path::new(file), ExecutableKind::File).map(|c| c.class)
        };
        assert_eq!(
            class("/usr/bin/chromium", "/usr/lib/chromium/chromium"),
            Some(Chromium)
        );
        // Debian's alternatives: x-www-browser → firefox-esr.
        assert_eq!(
            class("/usr/bin/x-www-browser", "/usr/lib/firefox-esr/firefox-esr"),
            Some(Firefox)
        );
        // An alternatives name that resolved to something unknown may start anything.
        assert_eq!(
            class("/usr/bin/x-www-browser", "/opt/x/browser.sh"),
            Some(Launcher)
        );
        // Snap: the typed name is the browser.
        assert_eq!(class("/snap/bin/firefox", "/usr/bin/snap"), Some(Firefox));
        // A symlink to a browser under another name.
        assert_eq!(
            class("/home/me/bin/web", "/opt/google/chrome/google-chrome"),
            Some(Chromium)
        );
        assert_eq!(class("/usr/bin/curl", "/usr/bin/curl"), None);
        assert_eq!(
            classify(
                Path::new("/usr/bin/xdg-open"),
                Path::new("/usr/bin/xdg-open"),
                ExecutableKind::File
            ),
            Some(AppClassInfo {
                class: Launcher,
                name: "xdg-open".into(),
                bundle_id: None
            })
        );
        if cfg!(target_os = "macos") {
            assert_eq!(class("/usr/bin/open", "/usr/bin/open"), Some(Launcher));
        } else {
            assert_eq!(class("/usr/bin/open", "/usr/bin/open"), None);
        }
    }

    #[test]
    fn a_process_runs_the_program_by_file_bundle_or_script_name() {
        let program = Path::new("/opt/fake/chromium");
        assert!(runs_program(Some(program), "chromium", program, None));
        // A script: the OS shows its interpreter's file, and (Linux) the script's name.
        assert!(runs_program(
            Some(Path::new("/usr/bin/dash")),
            "chromium",
            program,
            None
        ));
        assert!(!runs_program(
            Some(Path::new("/usr/bin/dash")),
            "dash",
            program,
            None
        ));
        assert!(!runs_program(None, "", program, None));
        // Any file of the same bundle (a helper of the browser).
        let bundle = Path::new("/Applications/Fake.app");
        let main = bundle.join("Contents/MacOS/Fake");
        let helper = bundle.join("Contents/Frameworks/Fake Helper.app/Contents/MacOS/Fake Helper");
        assert!(runs_program(
            Some(&helper),
            "Fake Helper",
            &main,
            Some(bundle)
        ));
        assert!(!runs_program(
            Some(Path::new(
                "/Applications/Fake Other.app/Contents/MacOS/Fake"
            )),
            "Fakeish",
            &main,
            Some(bundle)
        ));
        // Names are compared as the OS cuts them.
        let long = Path::new("/usr/bin/google-chrome-unstable");
        let cut = if cfg!(target_os = "linux") {
            "google-chrome-u"
        } else {
            "google-chrome-unstable"
        };
        assert!(runs_program(None, cut, long, None));
    }

    #[test]
    fn a_process_of_the_tree_is_never_elsewhere() {
        // A copy of sleep under a name of its own: no other process of this user runs it.
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("vpnm-class-probe");
        std::fs::copy("/bin/sleep", &program).unwrap();
        let program = program.canonicalize().unwrap();
        let mut child = std::process::Command::new(&program)
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let table = loop {
            let table = super::super::proc::snapshot().unwrap();
            if table.contains_key(&pid) || std::time::Instant::now() > deadline {
                break table;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let found = same_program_elsewhere(&table, &Tree::new(), &program, None);
        assert_eq!(found.map(|p| p.pid), Some(pid));
        let tree = Tree::from([(pid, table[&pid].started_us)]);
        assert_eq!(same_program_elsewhere(&table, &tree, &program, None), None);
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
