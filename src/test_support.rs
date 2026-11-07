use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        let base = option_env!("CARGO_TARGET_TMPDIR")
            .unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/target/test-tmp"));
        std::fs::create_dir_all(base).unwrap();
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(base).join(format!("{label}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Keep the artifacts of a failing test for debugging.
        if std::thread::panicking() {
            return;
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Whether `name` can be run. A cross toolchain is absent on most CI runners, so a
/// test needing one skips rather than fails; `WELD_REQUIRE_TOOLS=1` turns that
/// skip back into a failure, for a machine that is supposed to have the tool.
#[allow(dead_code)]
pub fn tool_available(name: &str) -> bool {
    let found = std::process::Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    assert!(
        found || std::env::var_os("WELD_REQUIRE_TOOLS").is_none(),
        "{name} is not installed and WELD_REQUIRE_TOOLS is set"
    );
    found
}

/// The `weld` executable beside this test binary. `cargo test` builds it as part of
/// the bin target; `cargo test --lib` does not, so say which command is missing rather
/// than failing later on an absent program.
#[allow(dead_code)]
pub fn weld_binary() -> String {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    let weld = path.join("weld");
    assert!(
        weld.is_file(),
        "{} is not built: run `cargo build --bin weld`",
        weld.display()
    );
    weld.to_string_lossy().into_owned()
}
