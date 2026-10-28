use std::process::ExitCode;

fn main() -> ExitCode {
    match planguard::cli::run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}
