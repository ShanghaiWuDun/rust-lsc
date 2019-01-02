#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ansi_term;
extern crate chrono;
extern crate lsc;


use lsc::AuthData;
use lsc::download_rpm_or_deb_packages_over_ssh;



use crate::log::{ Record, Level, Metadata, SetLoggerError, LevelFilter, };
use crate::ansi_term::{ Color, Style, };
use crate::chrono::Local;

static LOGGER: SimpleLogger = SimpleLogger;
struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        let module_path = record.module_path().unwrap_or("");
        
        if (module_path.starts_with("lsc") || module_path.starts_with("thrussh")) && self.enabled(record.metadata()) {
            println!("[{:5} {} {}:{} {}] {}",
                        match record.level() {
                            Level::Error => Color::Red.paint("ERROR"),
                            Level::Warn  => Color::Yellow.paint("WARN "),
                            Level::Info  => Color::Green.paint("INFO "),
                            Level::Debug => Color::Blue.paint("DEBUG"),
                            Level::Trace => Color::Purple.paint("TRACE"),
                        },
                        Local::now().to_rfc3339(),
                        record.file().unwrap_or(""),
                        record.line().unwrap_or(0),
                        Style::new().dimmed().paint(module_path),
                        record.args());
        }
    }

    fn flush(&self) { }
}

pub fn init() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Trace))
}




fn test_ssh2() {
    let raw_key =
"-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,04E841069474CB140263

6HBi//GyCpcRsk5kMgVoITlY+v2K0hqAwlE9IMK/Yct2YxusDhu6X6bAH6uDHMKd
.......................
.......................
g3yWlUWB0Co8ohRVAy9zKiJ2hk9Us0kQUhjvaoT/WBbExWsXP7JpkoAAwfBfaELf
-----END RSA PRIVATE KEY-----";
    
    let identity = AuthData::Pubkey{ pem_bytes: raw_key, key_passwd: Some("password....") };
    match download_rpm_or_deb_packages_over_ssh("127.0.0.1:22", "ubuntu", identity) {
        Ok(packages_str) => {
            println!("{}", packages_str);
        },
        Err(e) => {
            error!("{:?}", e);
        }
    }
}


fn main () {
    init().unwrap();

    test_ssh2();
}