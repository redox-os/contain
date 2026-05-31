use std::{
    fs,
    os::unix::process::CommandExt,
    process::{exit, Command},
};

use libredox::call::waitpid;
use log::{debug, error};

use crate::{ContainConfig, ContainError, ContainResult, ContainThread, CONTAIN_EXEC_FAIL_EXIT};

/// Spawn and execute a command with no namespace changes.
/// Used to execute a root shell.
pub fn run_not_contained(mut command: Command) -> ContainResult<i32> {
    let mut child = command.spawn().map_err(|e| {
        error!("failed to spawn uncontained command");
        ContainError::io_error(e)
    })?;
    match child
        .wait()
        .map_err(|e| {
            error!("failed to wait on uncontained command");
            ContainError::io_error(e)
        })?
        .code()
    {
        Some(code) => Ok(code),
        None => Ok(1),
    }
}

/// Create a filtered scheme thread in a new namespace which will provide
/// sandboxed proxy schemes as described in the config.
/// Then fork and execute a command in that sandboxed namespace.
pub fn run_contained(config: ContainConfig, command: Command) -> ContainResult<i32> {
    let config = validate_config(config)?;
    let contain_thread = ContainThread::new(config).map_err(|e| {
        error!("could not get contain thread: {}", e);
        e
    })?;

    run_in_namespace(command, contain_thread.namespace())
}

/// List all schemes.
fn list_schemes() -> ContainResult<Vec<String>> {
    let mut scheme_names = Vec::new();

    for entry_result in fs::read_dir(":").map_err(|e| ContainError::io_error(e))? {
        let entry = entry_result.map_err(|e| ContainError::io_error(e))?;

        if let Some(name_str) = entry.file_name().to_str() {
            scheme_names.push(name_str.to_string());
        }
    }
    Ok(scheme_names)
}

/// Validate the config.
/// Remove duplicate schemes and schemes that are not available.
/// Remove a filtered file or directory if it is not a in sandboxed scheme.
fn validate_config(mut config: ContainConfig) -> ContainResult<ContainConfig> {
    let schemes = list_schemes()?;
    debug!("schemes: {:?}", schemes);
    // quietly remove duplicates and ignore non-existent schemes
    config.pass_schemes.sort();
    config.pass_schemes.dedup();
    config.pass_schemes.retain(|scheme| {
        let is_known = schemes.contains(scheme);
        if !is_known {
            debug!("{scheme} is not recognized");
        }
        is_known
    });
    config.sandbox_schemes.sort();
    config.sandbox_schemes.dedup();
    config.sandbox_schemes.retain(|scheme| {
        let is_known = schemes.contains(scheme);
        if !is_known {
            debug!("{scheme} is not recognized");
        }
        is_known
    });
    // Error if the chroot is not a sandboxed scheme
    if config.root.is_some()
        && !config.sandbox_schemes.iter().any(|scheme| {
            config
                .root
                .as_ref()
                .unwrap()
                .starts_with(&format!("{}:", scheme))
        })
    {
        error!("root {} is not in a sandboxed scheme", config.root.unwrap());
        return Err(ContainError::ConfigError);
    }
    // Quietly remove any files or directories that are not
    // in a sandboxed scheme
    config.files.sort();
    config.files.dedup();
    config.files.retain(|f| {
        config
            .sandbox_schemes
            .iter()
            .any(|scheme| f.starts_with(&format!("{scheme}:")))
    });
    config.dirs.sort();
    config.dirs.dedup();
    config.dirs.retain(|d| {
        config
            .sandbox_schemes
            .iter()
            .any(|scheme| d.starts_with(&format!("{scheme}:")))
    });
    config.rofiles.sort();
    config.rofiles.dedup();
    config.rofiles.retain(|f| {
        config
            .sandbox_schemes
            .iter()
            .any(|scheme| f.starts_with(&format!("{scheme}:")))
    });
    config.rodirs.sort();
    config.rodirs.dedup();
    config.rodirs.retain(|d| {
        config
            .sandbox_schemes
            .iter()
            .any(|scheme| d.starts_with(&format!("{scheme}:")))
    });
    debug!("validated: {:?}", &config);
    Ok(config)
}

/// After the new namespace has been created, run the command in that namespace.
/// Once the command completes, terminate the namesapce thread.
pub fn run_in_namespace(mut command: Command, namespace: usize) -> ContainResult<i32> {
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        let e = std::io::Error::last_os_error();
        error!("contain: fork failed, {}", e);
        return Err(ContainError::io_error(e));
    }
    let pid = pid as usize;
    if pid == 0 {
        libredox::call::setrens(namespace, namespace).map_err(|e| {
            error!("child failed to enter restricted namespace, {}", e);
            ContainError::syscall_error(e.into())
        })?;

        let err = command.exec();

        error!("failed to launch {:?}: {}", command, err);
        exit(CONTAIN_EXEC_FAIL_EXIT);
    } else {
        let mut status = 0;
        let _ = waitpid(pid, &mut status, 0).map_err(|e| {
            error!("waitpid({}) returned error: {}", pid, e);
            ContainError::syscall_error(e.into())
        })?;

        // loop {
        //     let mut c_status = 0;
        //     let c_pid = waitpid(0, &mut c_status, libc::WNOHANG).unwrap_or_else(|e| {
        //         error!("waitpid(any) returned error: {}", e);
        //         0
        //     });
        //     if c_pid == 0 {
        //         break;
        //     } else {
        //         debug!("contain: container zombie {}: {:X}", c_pid, c_status);
        //     }
        // }

        debug!(
            "contain: Container {}, pid {}: exit: {:X}",
            namespace, pid, status
        );
        Ok(status)
    }
}
