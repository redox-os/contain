use contain::{run_contained, ContainConfig, CONTAIN_EXEC_FAIL_EXIT};
use log::{debug, error, info, LevelFilter};
use redox_log::{OutputBuilder, RedoxLogger};
use std::env;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().collect();

    let debug_level = match args.len() {
        1 => LevelFilter::Info,
        2 if args[1] == "-d" => LevelFilter::Debug,
        2 if args[1] == "-q" => LevelFilter::Error,
        2 => panic!(
            "Unknown argument, {}. Use {} -d for debug mode, -q for quieter",
            args[1], args[0]
        ),
        _ => panic!("Unsupported arguments: {:?}", args),
    };

    // Ignore possible errors while enabling logging
    let _ = RedoxLogger::new()
        .with_output(
            OutputBuilder::stdout()
                .with_filter(debug_level)
                .with_ansi_escape_codes()
                .build(),
        )
        .with_process_name("contain_test".into())
        .enable();

    let mut succeeded = 0;
    let mut failed = 0;
    let tests = [test_exec, test_pass_schemes, test_sandbox_schemes, test_read_only];
    for test in tests {
        let (s, f) = test();
        succeeded += s;
        failed += f;
    }
    println!("Contain Tests: {} succeeded, {} failed.", succeeded, failed);
}

fn test_exec() -> (u32, u32) {
    info!("test_exec");
    let mut succeeded = 0;
    let mut failed = 0;

    // exec a command not in the config
    let mut config = ContainConfig::default();
    config.pass_schemes.push("thisproc".to_string());
    config.pass_schemes.push("rand".to_string());
    let command = Command::new("file:/bin/ls");
    match run_contained(config, command) {
        Ok(exit_code) if exit_code == CONTAIN_EXEC_FAIL_EXIT * 256 => {
            debug!("empty scheme test succeeded: {:x}", exit_code);
            succeeded += 1;
        }
        Ok(exit_code) => {
            error!("empty scheme test failed: {:x}", exit_code);
            failed += 1;
        }
        Err(e) => {
            error!("empty scheme test failed: {:?}", e);
            failed += 1;
        }
    }

    // exec a command in the config
    let mut config = ContainConfig::default();
    config.pass_schemes.push("thisproc".to_string());
    config.pass_schemes.push("rand".to_string());
    config.sandbox_schemes.push("file".to_string());
    config.rofiles.push("file:/bin/cat".to_string());
    config.rofiles.push("file:/bin/coreutils".to_string());
    config.rofiles.push("file:/etc/passwd".to_string());
    let mut command = Command::new("file:/bin/cat");
    command.arg("file:/etc/passwd");
    match run_contained(config, command) {
        Ok(exit_code) if exit_code == 0 => {
            debug!("exec test succeeded");
            succeeded += 1;
        }
        Ok(exit_code) => {
            error!("exec test failed, exit code: {:x}", exit_code);
            failed += 1;
        }
        Err(e) => {
            error!("exec test failed: {:?}", e);
            failed += 1;
        }
    }
    (succeeded, failed)
}

fn test_pass_schemes() -> (u32, u32) {
    info!("test_pass_schemes");
    let mut succeeded = 0;
    let mut failed = 0;

    // read from a scheme we don't include
    // let mut config = ContainConfig::default();
    // config.pass_schemes.push("thisproc".to_string());
    // config.pass_schemes.push("rand".to_string());
    // config.sandbox_schemes.push("file".to_string());
    // config.rofiles.push("file:/bin/cat".to_string());
    // config.rofiles.push("file:/bin/coreutils".to_string());
    // let mut command = Command::new("file:/bin/cat");
    // command.arg("null:");
    // match run_contained(config, command) {
    //     Ok(exit_code) if exit_code == 1 * 256 => {
    //         debug!("pass schemes test succeeded");
    //         succeeded += 1;
    //     }
    //     Ok(exit_code) => {
    //         error!("pass schemes test failed, exit code: {:x}", exit_code);
    //         failed += 1;
    //     }
    //     Err(e) => {
    //         error!("pass schemes test failed: {:?}", e);
    //         failed += 1;
    //     }
    // }

    // read from a scheme we do include
    let mut config = ContainConfig::default();
    config.pass_schemes.push("thisproc".to_string());
    config.pass_schemes.push("rand".to_string());
    config.pass_schemes.push("null".to_string());
    config.sandbox_schemes.push("file".to_string());
    config.rofiles.push("file:/bin/cat".to_string());
    config.rofiles.push("file:/bin/coreutils".to_string());
    let mut command = Command::new("file:/bin/cat");
    command.arg("null:");
    match run_contained(config, command) {
        Ok(exit_code) if exit_code == 0 => {
            debug!("pass schemes test succeeded");
            succeeded += 1;
        }
        Ok(exit_code) => {
            error!("pass schemes test failed, exit code: {:x}", exit_code);
            failed += 1;
        }
        Err(e) => {
            error!("pass schemes test failed: {:?}", e);
            failed += 1;
        }
    }
    (succeeded, failed)
}

fn test_sandbox_schemes() -> (u32, u32) {
    info!("test_sandbox_schemes");
    let mut succeeded = 0;
    let mut failed = 0;

    // try to access something not in the sandbox
    let mut config = ContainConfig::default();
    config.pass_schemes.push("thisproc".to_string());
    config.pass_schemes.push("rand".to_string());
    config.pass_schemes.push("null".to_string());
    config.sandbox_schemes.push("file".to_string());
    config.rofiles.push("file:/bin/dd".to_string());
    config.rofiles.push("file:/bin/coreutils".to_string());
    config.rofiles.push("file:/etc/passwd".to_string());
    let mut command = Command::new("file:/bin/dd");
    command.arg("if=file:/etc/passwd");
    command.arg("of=file:/tmp/passwd1");
    match run_contained(config, command) {
        Ok(exit_code) if exit_code == 1 * 256 => {
            debug!("sandbox schemes test succeeded");
            succeeded += 1;
        }
        Ok(exit_code) => {
            error!("sandbox schemes test failed, exit code: {:x}", exit_code);
            failed += 1;
        }
        Err(e) => {
            error!("sandbox schemes test failed: {:?}", e);
            failed += 1;
        }
    }

    // try to access something in the sandbox
    let mut config = ContainConfig::default();
    config.pass_schemes.push("thisproc".to_string());
    config.pass_schemes.push("rand".to_string());
    config.pass_schemes.push("null".to_string());
    config.sandbox_schemes.push("file".to_string());
    config.rofiles.push("file:/bin/dd".to_string());
    config.rofiles.push("file:/bin/coreutils".to_string());
    config.rofiles.push("file:/etc/passwd".to_string());
    config.dirs.push("file:/tmp".to_string());
    let mut command = Command::new("file:/bin/dd");
    command.arg("if=file:/etc/passwd");
    command.arg("of=file:/tmp/passwd1");
    match run_contained(config, command) {
        Ok(exit_code) if exit_code == 0 => {
            debug!("sandbox schemes test succeeded");
            succeeded += 1;
        }
        Ok(exit_code) => {
            error!("sandbox schemes test failed, exit code: {:x}", exit_code);
            failed += 1;
        }
        Err(e) => {
            error!("sandbox schemes test failed: {:?}", e);
            failed += 1;
        }
    }
    (succeeded, failed)
}

fn test_read_only() -> (u32, u32) {
    info!("test_read_only");
    let mut succeeded = 0;
    let mut failed = 0;

    // try to write to something that is read only
    let mut config = ContainConfig::default();
    config.pass_schemes.push("thisproc".to_string());
    config.pass_schemes.push("rand".to_string());
    config.pass_schemes.push("null".to_string());
    config.sandbox_schemes.push("file".to_string());
    config.rofiles.push("file:/bin/dd".to_string());
    config.rofiles.push("file:/bin/coreutils".to_string());
    config.rofiles.push("file:/etc/passwd".to_string());
    config.rofiles.push("file:/tmp/passwd2".to_string());
    let mut command = Command::new("file:/bin/dd");
    command.arg("if=file:/etc/passwd");
    command.arg("of=file:/tmp/passwd2");
    match run_contained(config, command) {
        Ok(exit_code) if exit_code == 1 * 256 => {
            debug!("read only test succeeded");
            succeeded += 1;
        }
        Ok(exit_code) => {
            error!("read only test failed, exit code: {:x}", exit_code);
            failed += 1;
        }
        Err(e) => {
            error!("read only test failed: {:?}", e);
            failed += 1;
        }
    }

    // try to access something in the sandbox
    let mut config = ContainConfig::default();
    config.pass_schemes.push("thisproc".to_string());
    config.pass_schemes.push("rand".to_string());
    config.pass_schemes.push("null".to_string());
    config.sandbox_schemes.push("file".to_string());
    config.rofiles.push("file:/bin/dd".to_string());
    config.rofiles.push("file:/bin/coreutils".to_string());
    config.rofiles.push("file:/etc/passwd".to_string());
    config.files.push("file:/tmp".to_string());
    config.files.push("file:/tmp/passwd2".to_string());
    let mut command = Command::new("file:/bin/dd");
    command.arg("if=file:/etc/passwd");
    command.arg("of=file:/tmp/passwd2");
    match run_contained(config, command) {
        Ok(exit_code) if exit_code == 0 => {
            debug!("read only test succeeded");
            succeeded += 1;
        }
        Ok(exit_code) => {
            error!("read only test failed, exit code: {:x}", exit_code);
            failed += 1;
        }
        Err(e) => {
            error!("read only test failed: {:?}", e);
            failed += 1;
        }
    }
    (succeeded, failed)
}