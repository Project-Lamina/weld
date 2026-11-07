//! `weld::link` returns the error the command line would print, and does not exit.

fn link(args: &[&str]) -> Result<(), String> {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    weld::link(&args)
}

#[test]
fn errors_come_back_as_messages() {
    assert_eq!(link(&["-o", "out"]), Err("no input files".to_string()));
    assert_eq!(
        link(&["no-such-input.o", "-o", "out"]),
        Err("could not read the input objects".to_string())
    );
    assert!(
        link(&["--archive", "x.o"])
            .unwrap_err()
            .contains("requires -o")
    );
}

#[test]
fn command_line_only_flags_are_refused() {
    for flag in ["--help", "--version"] {
        assert!(link(&[flag]).unwrap_err().contains("command line options"));
    }
}
