fn main() {
    std::process::exit(sdl_cli::app::run_service_process(
        std::env::args().collect(),
    ));
}
