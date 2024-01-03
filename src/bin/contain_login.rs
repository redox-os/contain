use contain::{run_contained, run_not_contained, ContainConfig};
use libredox::{flag::O_RDONLY, Fd};
use log::LevelFilter;
use redox_log::{OutputBuilder, RedoxLogger};
use std::{
    env,
    io::{stdin, stdout, Error, Result, Write},
};
use termion::input::TermRead;

use redox_users::{All, AllUsers, Config};

/// contain_login:
/// Login as user, with restricted access to files, directories and schemes.
/// Logging in with uid==0 will not have any restrictions.
///
/// The list of files, directories and schemes is read from the CONTAIN_FILE.
/// The user's home directory is added as a writable directory.
/// A thread is started to manage proxy schemes that do the filtering.
/// Schemes that are allowed but not proxied are kept in the namespace.
/// Schemes that are not allowed are dropped from the namespace.
/// Files and directories that are permitted are opened using fd forwarding.
///
/// The user's shell is forked and exec'd in the modified namespace.
/// When a file is opened in one of the proxied schemes, it is checked against
/// the list of files and directories that are permitted.
/// Files that include O_RDWR or O_WRONLY flags are not permitted if they
/// are listed as rofiles or rodirs in the CONTAIN_FILE.
/// When the user's shell exits, the proxy schemes are shut down and
/// the namespace is dropped.
/// Note that there does not currently exist a means to delete the namespace
/// in the kernel, so it is leaked.

const ISSUE_FILE: &str = "/etc/issue";
const MOTD_FILE: &str = "/etc/motd";
const CONTAIN_FILE: &str = "/etc/contain.toml";

fn setup_logging(level: LevelFilter) -> Option<&'static RedoxLogger> {
    let mut logger = RedoxLogger::new().with_output(
        OutputBuilder::stderr()
            .with_filter(level) // limit global output to important info
            .with_ansi_escape_codes()
            .flush_on_newline(true)
            .build(),
    );

    #[cfg(target_os = "redox")]
    match OutputBuilder::in_redox_logging_scheme("contain", "contain", "contain.log") {
        Ok(b) => {
            logger = logger.with_output(
                // TODO: Add a configuration file for this
                b.with_filter(level).flush_on_newline(true).build(),
            )
        }
        Err(error) => eprintln!("contain: failed to create contain.log: {}", error),
    }

    #[cfg(target_os = "redox")]
    match OutputBuilder::in_redox_logging_scheme("contain", "contain", "contain.ansi.log") {
        Ok(b) => {
            logger = logger.with_output(
                b.with_filter(LevelFilter::Info)
                    .with_ansi_escape_codes()
                    .flush_on_newline(true)
                    .build(),
            )
        }
        Err(error) => eprintln!("contain: failed to create contain.ansi.log: {}", error),
    }

    match logger.enable() {
        Ok(logger_ref) => {
            if level > LevelFilter::Error {
                eprintln!("contain: enabled logger, level {}", level);
            }
            Some(logger_ref)
        }
        Err(error) => {
            eprintln!("contain: failed to set default logger: {}", error);
            None
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let debug_level = match args.len() {
        1 => LevelFilter::Error,
        2 if args[1] == "-d" => LevelFilter::Debug,
        2 => panic!(
            "Unknown argument, {}. Use {} -d for debug mode.",
            args[1], args[0]
        ),
        _ => panic!("Unsupported arguments: {:?}", args),
    };

    setup_logging(debug_level);

    let mut stdout = stdout();

    if let Ok(issue_fd) = Fd::open(ISSUE_FILE, O_RDONLY, 0) {
        let mut buf = [0 as u8; 1024];
        if let Ok(count) = issue_fd.read(&mut buf) {
            if count > 0 {
                stdout.write(&buf[0..count])?;
                stdout.flush()?;
            }
        }
    }

    loop {
        let user = liner::Context::new().read_line(
            liner::Prompt::from("\x1B[1mredox login:\x1B[0m "),
            None,
            &mut liner::BasicCompleter::new(Vec::<String>::new()),
        )?;

        if user.is_empty() {
            stdout.write(b"\n")?;
            stdout.flush()?;
            continue;
        }

        let stdin = stdin();
        let mut stdin = stdin.lock();
        let sys_users = AllUsers::authenticator(Config::default())
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

        let user = match sys_users.get_by_name(user) {
            None => {
                stdout.write(b"\nLogin incorrect\n")?;
                stdout.write(b"\n")?;
                stdout.flush()?;
                None
            }
            Some(user) if user.is_passwd_blank() => {
                if let Ok(motd) = Fd::open(MOTD_FILE, O_RDONLY, 0) {
                    let mut buf = [0 as u8; 1024];
                    if let Ok(count) = motd.read(&mut buf) {
                        if count > 0 {
                            stdout.write(&buf[0..count])?;
                            stdout.flush()?;
                        }
                    }
                }

                Some(user)
            }
            Some(user) => {
                stdout.write_all(b"\x1B[1mpassword:\x1B[0m ")?;
                stdout.flush()?;
                if let Ok(Some(password)) = stdin.read_passwd(&mut stdout) {
                    stdout.write(b"\n")?;
                    stdout.flush()?;

                    if user.verify_passwd(&password) {
                        if let Ok(motd) = Fd::open(MOTD_FILE, O_RDONLY, 0) {
                            let mut buf = [0 as u8; 1024];
                            if let Ok(count) = motd.read(&mut buf) {
                                if count > 0 {
                                    stdout.write(&buf[0..count])?;
                                    stdout.flush()?;
                                }
                            }
                        }
                        Some(user)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        if user.is_none() {
            continue;
        }

        let user = user.unwrap();

        if user.uid == 0 {
            let command = user.shell_cmd();

            let _ = run_not_contained(command);
        } else {
            if let Ok(mut config) = ContainConfig::from_file(CONTAIN_FILE) {
                config.add_dir(&user.home);
                let _ = run_contained(config, user.shell_cmd());
            }
        }

        stdout.write(b"\n")?;
        stdout.flush()?;

        if let Ok(issue_fd) = Fd::open(ISSUE_FILE, O_RDONLY, 0) {
            let mut buf = [0 as u8; 1024];
            if let Ok(count) = issue_fd.read(&mut buf) {
                if count > 0 {
                    stdout.write(&buf[0..count])?;
                    stdout.flush()?;
                }
            }
        }
    }
}
