mod app;
mod config;
mod http;
mod server;

fn main() -> std::process::ExitCode {
    app::main_exit_code()
}
