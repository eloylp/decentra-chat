use decentra_chat::cli;
use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run_from(std::env::args_os(), std::io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
