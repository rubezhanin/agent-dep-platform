use clap::CommandFactory;

#[test]
fn cli_parses_help() {
    let cmd = crate::Cli::command();
    let help = cmd.clone().render_help();
    assert!(help.to_string().contains("agency"));
}

#[test]
fn cli_has_deploy_and_status_subcommands() {
    let cmd = crate::Cli::command();
    let names: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
    assert!(names.contains(&"deploy"));
    assert!(names.contains(&"status"));
}
