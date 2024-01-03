mod contain_config;
mod contain_thread;
mod filterscheme;
mod runner;

pub use contain_config::ContainConfig;
pub use contain_thread::ContainThread;
pub use runner::{run_contained, run_in_namespace, run_not_contained};

// TODO: Check ownership of files (e.g. pty:/5) before making them visible
// TODO: Add tests
// TODO: Implement delete/drop of namespace in the kernel
// TODO: Re-implement path filtering when Rust Path supports Redox
// TODO: Discuss the future of the chroot-incompatible fpath syscall,
// since it doesn't work for forwarded descriptors

pub const CONTAIN_EXEC_FAIL_EXIT: i32 = 13;

pub type ContainResult<T> = core::result::Result<T, ContainError>;

#[derive(Debug)]
pub enum ContainError {
    ParseError,
    ConfigError,
    IoError(std::io::Error),
    SyscallError(libredox::error::Error),
    PoisonError,
    ThreadError,
}

impl ContainError {
    pub fn io_error(e: std::io::Error) -> Self {
        Self::IoError(e)
    }

    pub fn syscall_error(e: syscall::Error) -> Self {
        Self::SyscallError(e)
    }

    pub fn poison_error<T>(_e: std::sync::PoisonError<T>) -> Self {
        Self::PoisonError
    }
}

impl std::fmt::Display for ContainError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}
