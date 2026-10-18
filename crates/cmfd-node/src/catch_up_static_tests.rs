//! Only the desktop wallet turns the catch-up on. The server, pool and
//! exchange entry points never name the setter, and outside tests only the
//! wallet runtime's `start_embedded_node` uses it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The setter's name, spelled so that this file does not match itself.
const SETTER: &str = concat!("enable_wallet", "_catch_up");

#[test]
fn server_pool_and_exchange_code_never_names_the_catch_up_setter() {
    for (name, text) in [
        ("main.rs", include_str!("main.rs")),
        ("pool.rs", include_str!("pool.rs")),
        (
            "production_v4_pool.rs",
            include_str!("production_v4_pool.rs"),
        ),
        ("exchange_rpc.rs", include_str!("exchange_rpc.rs")),
    ] {
        assert!(!text.contains(SETTER), "{name} names {SETTER}");
    }
}

/// Every `.rs` file under `dir`, skipping build output, dependencies and
/// hidden directories.
fn rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !name.starts_with('.')
                && !matches!(
                    name.as_str(),
                    "target" | "node_modules" | "dist" | "third_party"
                )
            {
                rust_files(&path, files);
            }
        } else if name.ends_with(".rs") {
            files.push(path);
        }
    }
}

const MOD_STARTS: [&str; 3] = ["mod ", "pub mod ", "pub(crate) mod "];

/// The attribute lines just above line `position` of `lines`, joined: up to
/// a blank line or the end of the item before (`;`, `{` or `}`).
fn attributes_above(lines: &[&str], position: usize) -> String {
    lines[..position]
        .iter()
        .rev()
        .take_while(|line| {
            let line = line.trim();
            !line.is_empty() && !line.ends_with([';', '{', '}'])
        })
        .filter(|line| !line.trim_start().starts_with("//"))
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

/// The comma-separated arguments at the top level of the parentheses that
/// open at the start of `text`.
fn arguments(text: &str) -> Option<Vec<&str>> {
    let inner = text.strip_prefix('(')?;
    let mut depth = 0;
    let mut start = 0;
    let mut parts = Vec::new();
    for (at, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => {
                parts.push(&inner[start..at]);
                return Some(parts);
            }
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&inner[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    None
}

/// Whether `attributes` hold a `cfg` that compiles only for tests: `test`
/// itself, or an `all(...)` with `test` as one of its own predicates. A
/// feature such as `production-v3-testnet`, `not(test)` and
/// `any(test, ...)` do not count.
fn names_test(attributes: &str) -> bool {
    let compact = attributes
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    compact
        .split("#[cfg")
        .skip(1)
        .any(|rest| match arguments(rest).as_deref() {
            Some(["test"]) => true,
            Some([single]) => single
                .strip_prefix("all")
                .and_then(arguments)
                .is_some_and(|parts| parts.contains(&"test")),
            _ => false,
        })
}

/// Whether line `index` of `lines` lies in a top-level module whose `cfg`
/// attribute names `test`: walking up, a module opens before any closing
/// brace at the start of a line.
fn in_test_module(lines: &[&str], index: usize) -> bool {
    for (position, line) in lines[..index].iter().enumerate().rev() {
        if line.starts_with('}') {
            return false;
        }
        if MOD_STARTS.iter().any(|start| line.starts_with(start)) {
            return names_test(&attributes_above(lines, position));
        }
    }
    false
}

/// The files that `file` (with text `text`) declares as modules under a `cfg`
/// naming `test`, resolved as rustc does: a `#[path]` is relative to the
/// declaring file's directory, and `mod name;` lives in that file's module
/// directory.
fn test_only_children(file: &Path, text: &str) -> Vec<PathBuf> {
    let Some(dir) = file.parent() else {
        return Vec::new();
    };
    let own_dir = match file.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") | None => dir.to_path_buf(),
        Some(stem) => dir.join(stem),
    };
    let lines = text.lines().collect::<Vec<_>>();
    let mut children = Vec::new();
    for (position, line) in lines.iter().enumerate() {
        let Some(name) = MOD_STARTS
            .iter()
            .find_map(|start| line.trim().strip_prefix(start))
            .and_then(|rest| rest.strip_suffix(';'))
        else {
            continue;
        };
        let attributes = attributes_above(&lines, position);
        if !names_test(&attributes) {
            continue;
        }
        let path = attributes
            .split("#[path = \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next());
        children.push(match path {
            Some(path) => dir.join(path),
            None => own_dir.join(format!("{name}.rs")),
        });
    }
    children
}

/// The top-level function that line `index` of `lines` lies in, if any.
fn enclosing_function<'a>(lines: &[&'a str], index: usize) -> Option<&'a str> {
    for line in lines[..=index].iter().rev() {
        if line.starts_with('}') {
            return None;
        }
        for start in ["fn ", "pub fn ", "pub(crate) fn "] {
            if let Some(rest) = line.strip_prefix(start) {
                return rest.split(['(', '<']).next();
            }
        }
    }
    None
}

/// The 1-based lines of `text` that use the setter, called or named as a
/// path, outside comments and its own definition.
fn uses(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            !line.trim_start().starts_with("//")
                && line
                    .match_indices(SETTER)
                    .any(|(at, _)| !line[..at].trim_end().ends_with("fn"))
        })
        .map(|(index, _)| index + 1)
        .collect()
}

fn canonical(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

/// Every `.rs` file in `files` whose declaring module names `test` in a
/// `cfg`, so it is compiled only for tests.
fn test_only_files(files: &[PathBuf]) -> HashSet<PathBuf> {
    let mut test_only = HashSet::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        test_only.extend(
            test_only_children(file, &text)
                .iter()
                .filter_map(|child| canonical(child)),
        );
    }
    test_only
}

#[test]
fn only_the_desktop_wallet_runtime_and_tests_use_the_catch_up_setter() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    let test_only = test_only_files(&files);
    let mut wallet_uses = Vec::new();
    let mut test_uses = 0;
    let mut elsewhere = Vec::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let lines = text.lines().collect::<Vec<_>>();
        let test_file = canonical(path).is_some_and(|path| test_only.contains(&path));
        let ours =
            relative.starts_with("apps/wallet/") || relative.starts_with("crates/cmfd-node/");
        for line in uses(&text) {
            if ours && (test_file || in_test_module(&lines, line - 1)) {
                test_uses += 1;
            } else if relative.starts_with("apps/wallet/") {
                wallet_uses.push(format!(
                    "{relative}:{}",
                    enclosing_function(&lines, line - 1).unwrap_or("?")
                ));
            } else {
                elsewhere.push(format!("{relative}:{line}"));
            }
        }
    }
    assert!(elsewhere.is_empty(), "{SETTER} is used at {elsewhere:?}");
    assert_eq!(
        wallet_uses,
        ["apps/wallet/src-tauri/src/runtime.rs:start_embedded_node"],
        "outside tests only start_embedded_node may use {SETTER}"
    );
    assert!(test_uses > 0, "the scan found no test uses");
}

#[test]
fn the_use_scan_tells_uses_tests_and_other_code_apart() {
    let call = format!("    node.{SETTER}(sources);");
    assert_eq!(uses(&call), [1]);
    assert_eq!(
        uses(&format!("    Node::{SETTER} (&mut node, sources)")),
        [1]
    );
    assert_eq!(
        uses(&format!("    let on = sources.map(Node::{SETTER});")),
        [1]
    );
    assert_eq!(uses(&format!("    let turn_on = Node::{SETTER};")), [1]);
    assert!(uses(&format!("    pub fn {SETTER}(")).is_empty());
    assert!(
        uses(&format!(
            "    /// [`Node::{SETTER}`] turns it on: {SETTER}(sources)"
        ))
        .is_empty()
    );
    assert!(uses(&format!("    // {SETTER}(sources)")).is_empty());
    let text = format!(
        "fn run() {{\n{call}\n}}\n\n#[cfg(test)]\nmod tests {{\n    fn case() {{\n{call}\n    }}\n}}\n\nfn after() {{\n{call}\n}}\n"
    );
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(uses(&text), [2, 8, 13]);
    assert!(!in_test_module(&lines, 1));
    assert!(in_test_module(&lines, 7));
    assert!(!in_test_module(&lines, 12));
    assert_eq!(enclosing_function(&lines, 1), Some("run"));
    assert_eq!(enclosing_function(&lines, 7), None);
    assert_eq!(enclosing_function(&lines, 12), Some("after"));
    let text = format!(
        "#[cfg(all(\n    test,\n    not(feature = \"x\")\n))]\nmod tests {{\n{call}\n}}\n\n/// Not for tests.\nmod other {{\n{call}\n}}\n"
    );
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(uses(&text), [6, 11]);
    assert!(in_test_module(&lines, 5));
    assert!(!in_test_module(&lines, 10));
    // A module right after a test-only one is not test-only.
    let text = format!(
        "#[cfg(test)]
mod a_tests;
mod b {{
{call}
}}
"
    );
    let lines = text.lines().collect::<Vec<_>>();
    assert!(!in_test_module(&lines, 3));

    assert!(names_test("#[cfg(test)]"));
    assert!(names_test(
        "#[cfg(all(
    test,
    feature = \"x\"
))]"
    ));
    assert!(names_test("#[cfg(all(feature = \"x\", test))]"));
    assert!(names_test(
        "#[cfg(all(test, any(feature = \"a\", feature = \"b\")))]"
    ));
    assert!(names_test("#[path = \"x_tests.rs\"]\n#[cfg(test)]"));
    assert!(!names_test("#[cfg(feature = \"production-v3-testnet\")]"));
    assert!(!names_test("#[cfg(not(test))]"));
    // Built into a release with the feature on, so not test-only.
    assert!(!names_test("#[cfg(any(test, feature = \"x\"))]"));
    assert!(!names_test("#[cfg(all(feature = \"x\", any(test, unix)))]"));
    assert!(!names_test("#[cfg_attr(test, allow(dead_code))]"));
    assert!(!names_test("#[path = \"x_tests.rs\"]"));
    assert!(
        test_only_children(
            Path::new("crates/x/src/lib.rs"),
            "#[cfg(feature = \"production-v3-testnet\")]
mod v3_tests;
#[cfg(feature = \"x\")]
#[path = \"x_tests.rs\"]
mod moved;
#[cfg(any(test, feature = \"x\"))]
mod shared_tests;
"
        )
        .is_empty()
    );
    let parent = "mod pruning;\n#[cfg(test)]\nmod pruning_tests;\n/// Runtime.\npub mod p2p_tests_off;\n#[cfg(all(test, feature = \"x\"))]\n#[path = \"moved_tests.rs\"]\nmod moved;\n";
    let base = Path::new("crates/x/src");
    assert_eq!(
        test_only_children(&base.join("lib.rs"), parent),
        [base.join("pruning_tests.rs"), base.join("moved_tests.rs")]
    );
    assert_eq!(
        test_only_children(&base.join("work_gate.rs"), parent),
        [
            base.join("work_gate").join("pruning_tests.rs"),
            base.join("moved_tests.rs")
        ]
    );
    // The real declarations: a plain child, a child in a module directory,
    // and a `#[path]` child; runtime files are not test-only.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root.join("crates/cmfd-node/src"), &mut files);
    let test_only = test_only_files(&files);
    let source = root.join("crates/cmfd-node/src");
    for (name, expected) in [
        ("pruning_tests.rs", true),
        ("work_gate/catch_up_tests.rs", true),
        ("p2p_catch_up_tests.rs", true),
        ("work_gate/catch_up.rs", false),
        ("pool.rs", false),
        ("p2p.rs", false),
    ] {
        let path = canonical(&source.join(name)).unwrap();
        assert_eq!(test_only.contains(&path), expected, "{name}");
    }
}
