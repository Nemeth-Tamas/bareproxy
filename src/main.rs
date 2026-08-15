mod app;
mod config;
pub mod crypto;
mod http;
mod proxy;
mod server;

fn main() -> std::process::ExitCode {
    app::main_exit_code()
}
