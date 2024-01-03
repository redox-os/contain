use std::sync::{Arc, LockResult, RwLock, RwLockReadGuard};
use std::thread::{self, JoinHandle};

use event::{EventFlags, RawEventQueue};
use libredox::call::setrens;
use libredox::{flag, Fd};
use log::{debug, error, warn};
use redox_scheme::{read_requests, write_responses, Request, SignalBehavior};

use crate::contain_config::ContainConfig;
use crate::filterscheme::FilterScheme;
use crate::{ContainError, ContainResult};

pub struct ContainThread {
    config: Arc<RwLock<ContainConfig>>,
    namespace: usize,
    shutdown_pipe: usize,
    thread_handle: JoinHandle<()>,
}

impl ContainThread {
    // Create the namespace and spawn the scheme manager(s).
    // We use an RwLock for the config so we can start with
    // the basic space and add the user directory after.
    pub fn new(config: ContainConfig) -> ContainResult<Self> {
        let config_arc = Arc::new(RwLock::new(config));
        let config_lock = config_arc.read().map_err(|e| {
            error!("could not get config lock: {}", e);
            ContainError::poison_error(e)
        })?;

        let mut pass_scheme_ptrs = Vec::new();
        for scheme in config_lock.pass_schemes.iter() {
            pass_scheme_ptrs.push([scheme.as_ptr() as usize, scheme.len()]);
        }

        let new_ns = syscall::mkns(&pass_scheme_ptrs).map_err(|e| {
            error!("could not create namespace, {}", e);
            ContainError::syscall_error(e)
        })?;

        setrens(-1isize as usize, new_ns).map_err(|e| {
            error!("failed to enter namespace, {}", e);
            ContainError::syscall_error(e)
        })?;

        let mut schemes = Vec::with_capacity(config_lock.sandbox_schemes.len());

        for scheme_name in config_lock.sandbox_schemes.iter() {
            let scheme_fd = Fd::open(
                &format!(":{}", &scheme_name),
                flag::O_CREAT | flag::O_RDWR | flag::O_CLOEXEC,
                0,
            )
            .map_err(|e| {
                error!("could not create scheme {}:, {}", scheme_name, e);
                ContainError::syscall_error(e)
            })?;
            let scheme_handler = FilterScheme::new(&scheme_name, config_arc.clone());
            schemes.push((scheme_fd, scheme_handler));
        }
        setrens(
            -1isize as usize,
            syscall::getns().map_err(|e| {
                error!("could not get namespace, {}", e);
                ContainError::syscall_error(e)
            })?,
        )
        .map_err(|e| {
            error!("could not update namespace, {}", e);
            ContainError::syscall_error(e)
        })?;

        let mut event_queue = RawEventQueue::new().map_err(|e| {
            error!("could not open event queue");
            ContainError::syscall_error(e)
        })?;

        // Register for events before splitting into threads, to avoid scheme event race condition
        for i in 0..schemes.len() {
            let (scheme_fd, _) = &schemes[i];
            event_queue
                .subscribe(scheme_fd.raw(), i, EventFlags::READ)
                .map_err(|e| {
                    error!(
                        "could not subscribe for event on scheme fd {}, {}",
                        scheme_fd.raw(),
                        e
                    );
                    ContainError::syscall_error(e)
                })?;
        }

        // Create a pipe to request shutdown when the user command completes
        let mut pipes = [0; 2];

        match unsafe {
            libc::pipe2(
                pipes.as_mut_ptr(),
                syscall::O_CLOEXEC as i32 | syscall::O_NONBLOCK as i32,
            )
        } {
            0 => Ok(()),
            -1 => {
                error!("could not create pipe");
                Err(ContainError::io_error(std::io::Error::last_os_error()))
            }
            _ => unreachable!(),
        }?;

        debug!("pipes {:?}", &pipes);
        let [read_pipe, write_pipe] = pipes;
        let read_pipe = read_pipe as usize;
        let write_pipe = write_pipe as usize;
        let pipe_index = schemes.len();

        event_queue
            .subscribe(read_pipe, pipe_index, EventFlags::READ)
            .map_err(|e| {
                error!(
                    "could not subscribe for event on pipe fd {}, {}",
                    read_pipe, e
                );
                ContainError::syscall_error(e)
            })?;

        drop(config_lock);

        let scheme_thread = thread::spawn(move || {
            'events: loop {
                let event = match event_queue.next() {
                    Some(Ok(event)) => {
                        debug!("got event {:?}", event);
                        if event.user_data == pipe_index {
                            debug!("got pipe event");
                            break 'events;
                        } else if event.user_data < schemes.len() {
                            debug!("got scheme event");
                            event
                        } else {
                            error!("event queue returned unexpected index: {}", event.user_data);
                            break 'events;
                        }
                    }
                    Some(Err(e)) => {
                        error!("event queue returned error {}", e);
                        break 'events;
                    }
                    None => {
                        warn!("event queue returned no data");
                        break 'events;
                    }
                };

                if event.user_data < schemes.len() {
                    let (scheme_fd, scheme_handler) = &schemes[event.user_data];

                    let mut requests = [Request::default()];
                    let n_requests = match read_requests(
                        scheme_fd.raw(),
                        &mut requests,
                        SignalBehavior::Restart,
                    ) {
                        Ok(0) => {
                            debug!("read socket closing, exiting");
                            break 'events;
                        }
                        Ok(n) => {
                            debug!("got {} events", n);
                            n
                        }
                        Err(e) => {
                            error!("error reading packet from scheme socket: {}", e);
                            break 'events;
                        }
                    };

                    for i in 0..n_requests {
                        let response = [requests[i].handle_scheme(scheme_handler)];
                        match write_responses(scheme_fd.raw(), &response, SignalBehavior::Restart) {
                            Ok(n) if n == response.len() => {}
                            Ok(n) => {
                                assert!(n != response.len());
                                debug!(
                                    "did not write response packets, expected {}, got {}",
                                    response.len(),
                                    n
                                );
                                break 'events;
                            }
                            Err(e) => {
                                error!("error writing response packet: {}", e);
                                break 'events;
                            }
                        };
                    }
                } else if event.user_data == pipe_index {
                    debug!("received event on shutdown pipe, exiting");
                    break 'events;
                } else {
                    error!("unknown index for event data, {}", event.user_data);
                    break 'events;
                }
            }
            // do cleanup
            for (scheme_fd, _) in schemes {
                let _ = scheme_fd.close();
            }
        });

        Ok(Self {
            config: config_arc,
            namespace: new_ns,
            shutdown_pipe: write_pipe,
            thread_handle: scheme_thread,
        })
    }

    pub fn namespace(&self) -> usize {
        self.namespace
    }

    pub fn thread(&self) -> &JoinHandle<()> {
        &self.thread_handle
    }

    pub fn config(&self) -> LockResult<RwLockReadGuard<ContainConfig>> {
        self.config.read()
    }
}

impl Drop for ContainThread {
    // Shutdown the thread by sending a message on the shutdown pipe
    // TODO: Implement drop of namespace
    fn drop(&mut self) {
        debug!("shutdown scheme thread");

        let _ = libredox::call::write(self.shutdown_pipe, "shutdown scheme".as_bytes());
    }
}
