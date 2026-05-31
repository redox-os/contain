use libc::{getgid, getuid};
use libredox::errno::*;
use libredox::flag::{O_CREAT, O_RDWR, O_WRONLY};
use log::{debug, error};
use redox_scheme::{scheme::SchemeSync, CallerCtx, OpenResult};
use syscall::{rmdir, unlink, Error, Result};

use std::io;
use std::path::Path;
use std::str;
use std::sync::{Arc, RwLock};

use crate::contain_config::ContainConfig;

/// Filter paths to only include the specified items.
/// Allow specified exact filename matches, regardless of types.
/// Allow paths starting with any of the specified directories.

struct IdGuard<const UID_NOT_GID: bool> {
    original: u32,
}

impl<const UID_NOT_GID: bool> IdGuard<UID_NOT_GID> {
    fn new(original: u32) -> Result<IdGuard<UID_NOT_GID>> {
        Ok(Self { original })
    }
}

impl<const UID_NOT_GID: bool> Drop for IdGuard<UID_NOT_GID> {
    fn drop(&mut self) {
        let res = if UID_NOT_GID {
            setreuid(self.original, self.original)
        } else {
            setregid(self.original, self.original)
        };
        if res.is_err() {
            if UID_NOT_GID {
                error!("CRITICAL: Failed to restore UID. UID may be stuck as another user.",);
            } else {
                error!("CRITICAL: Failed to restore GID. GID may be stuck as another group.",);
            }
        }
    }
}

fn setreuid(ruid: u32, euid: u32) -> Result<()> {
    let res = unsafe { libc::setreuid(ruid, euid) };
    if res < 0 {
        Err(Error::new(
            io::Error::last_os_error().raw_os_error().unwrap_or(EPERM),
        ))
    } else {
        Ok(())
    }
}

fn setregid(rgid: u32, egid: u32) -> Result<()> {
    let res = unsafe { libc::setregid(rgid, egid) };
    if res < 0 {
        Err(Error::new(
            io::Error::last_os_error().raw_os_error().unwrap_or(EPERM),
        ))
    } else {
        Ok(())
    }
}

pub struct FilterScheme {
    pub scheme: String,
    config: Arc<RwLock<ContainConfig>>,
}

impl FilterScheme {
    pub fn new(scheme: &str, config: Arc<RwLock<ContainConfig>>) -> FilterScheme {
        FilterScheme {
            scheme: scheme.to_string(),
            config,
        }
    }

    // Filter an absolute path (starts with a scheme name). Error on failure.
    fn is_allowed(&self, config: &ContainConfig, path: &str, flags: usize) -> Result<bool> {
        debug!("is_allowed: checking {}", path);
        // ensure there *is* a slash after the scheme name
        let path = if let Some((scheme, subpath)) = path.split_once(':') {
            if !scheme.contains('/') {
                format!("{}:/{}", scheme, subpath.trim_start_matches('/'))
            } else {
                path.to_string()
            }
        } else {
            path.to_string()
        };
        if config.root.is_some() && path.starts_with(config.root.as_ref().unwrap()) {
            debug!("canon_filter: is in root {}", path);
            Ok(true)
        } else if config.files.iter().any(|match_path| &path == match_path)
            || config.dirs.iter().any(|dir| path.starts_with(dir))
            || config.pass_schemes.iter().any(|dir| path.starts_with(dir))
            || ((flags & O_RDWR as usize == 0 || flags & O_WRONLY as usize == 0)
                && (config.rofiles.iter().any(|match_path| &path == match_path)
                    || config.rodirs.iter().any(|dir| path.starts_with(dir))))
        {
            debug!("canon_filter: matched {}", path);
            Ok(true)
        } else {
            debug!("canon_filter: failed {}", path);
            Err(Error::new(EPERM))
        }
    }

    // Add the scheme name. See if it matches the filter.
    // If it does, return the full path.
    // If it does not match the filter, add the chroot (if any).
    // The chrooted path is not checked against the filter as it will always succeed.
    fn real_path(&self, config: &ContainConfig, path: &str, flags: usize) -> String {
        let full_path = format!("{}:/{}", &self.scheme, path.trim_start_matches('/'));
        if self.is_allowed(config, &full_path, flags).is_err() && config.root.is_some() {
            format!(
                "{}/{}",
                config.root.as_ref().unwrap(),
                path.trim_start_matches('/')
            )
        } else {
            full_path
        }
    }

    // Check if this path is allowed. If yes, canonicalize it and check again.
    // If we are chroot'd, prefix the name with the root path if needed.
    // If we are in "create" mode and the file does not exist, canonicalize the parent dir.
    fn resolve(&self, config: &ContainConfig, path: &str, flags: usize) -> Result<String> {
        if path.contains("../") || path.ends_with("..") {
            debug!("path includes .. - {}", path);
            return Err(Error::new(EINVAL));
        }
        if config.root.is_some() {
            let full_path = format!("{}:/{}", &self.scheme, path.trim_start_matches('/'));
            if full_path.starts_with(config.root.as_ref().unwrap()) {
                debug!("path includes root, but we are chroot'd, {}", path);
                return Err(Error::new(EINVAL));
            }
        }
        let real_path = self.real_path(config, path, flags);
        debug!("resolve {}", real_path);
        let canon_path = if flags & O_CREAT as usize == 0 {
            let canon_path = Path::new(&real_path)
                .canonicalize()
                .map_err(|_| Error::new(EPERM))
                .and_then(|p| p.to_str().ok_or(Error::new(EINVAL)).map(|s| s.to_string()))?;
            self.is_allowed(config, &canon_path, flags)?;
            canon_path
        } else {
            // canonicalize the directory, then add the filename
            let filename = Path::new(&real_path)
                .file_name()
                .ok_or(Error::new(EINVAL))?
                .to_str()
                .ok_or(Error::new(EINVAL))?;
            let mut canon_path = Path::new(&real_path)
                .parent()
                .ok_or(Error::new(ENOENT))?
                .canonicalize()
                .map_err(|_| Error::new(ENOENT))?;
            self.is_allowed(
                config,
                &canon_path.to_str().ok_or(Error::new(EINVAL))?.to_string(),
                O_RDWR as usize,
            )?;
            canon_path.push(filename);
            canon_path.to_str().ok_or(Error::new(EINVAL))?.to_string()
        };
        Ok(canon_path)
    }
}

fn with_id_guards<F, R>(ctx: &CallerCtx, f: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    let original_gid = unsafe { getgid() };
    let original_uid = unsafe { getuid() };
    let _gid_guard = IdGuard::<false>::new(original_gid)?;
    let _uid_guard = IdGuard::<true>::new(original_uid)?;

    setregid(original_gid, ctx.gid as u32)?;
    setreuid(original_uid, ctx.uid as u32)?;

    f()
}

impl SchemeSync for FilterScheme {
    fn open(&mut self, path: &str, flags: usize, ctx: &CallerCtx) -> Result<OpenResult> {
        let config = self.config.read().map_err(|e| {
            error!("open could not get read lock: {}", e);
            Error::new(ENOTRECOVERABLE)
        })?;

        with_id_guards(ctx, || {
            let o_flags = (flags & 0xFFFF_0000) as i32;
            let mode = (flags & 0x0000_FFFF) as u16;
            let res = self
                .resolve(&config, path, flags)
                .and_then(|resolved| {
                    libredox::call::open(&resolved, o_flags, mode).map_err(syscall::Error::from)
                })
                .map(|fd| OpenResult::OtherScheme { fd });
            debug!("open({}), res={:?}", path, res.is_ok());
            res
        })
    }

    fn rmdir(&mut self, path: &str, ctx: &CallerCtx) -> Result<()> {
        debug!("rmdir({})", path);
        let config = self.config.read().map_err(|e| {
            error!("rmdir could not get read lock: {}", e);
            Error::new(ENOTRECOVERABLE)
        })?;

        with_id_guards(ctx, || {
            self.resolve(&config, path, 0)
                .and_then(|resolved| rmdir(resolved))
                .map(|_| ())
        })
    }

    fn unlink(&mut self, path: &str, ctx: &CallerCtx) -> Result<()> {
        debug!("unlink({})", path);
        let config = self.config.read().map_err(|e| {
            error!("unlink could not get read lock: {}", e);
            Error::new(ENOTRECOVERABLE)
        })?;

        with_id_guards(ctx, || {
            self.resolve(&config, path, 0)
                .and_then(|resolved| unlink(resolved))
                .map(|_| ())
        })
    }
}
