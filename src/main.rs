use clap::{Parser, Subcommand};
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read as _, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Monitors udev for storage media insertions and automatically writes an image.
#[derive(Parser, Debug)]
#[command(name = "autoflasher", version, about)]
struct Args {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Write an image to storage devices as they are inserted
    Flash {
        /// Path to the image file to write
        #[arg(short, long)]
        image: PathBuf,

        /// Skip confirmation prompt before writing (default: ask for confirmation)
        #[arg(long, default_value_t = false)]
        no_confirm: bool,

        /// Skip post-write verification (verification is on by default)
        #[arg(long, default_value_t = false)]
        skip_verify: bool,

        /// Only write to this specific device (e.g. /dev/sdb)
        #[arg(short, long)]
        device: Option<String>,

        /// Only watch for this media type: usb, sd, ata, scsi, nvme
        #[arg(short, long)]
        media_type: Option<String>,

        /// Exit after the first successful write
        #[arg(long, default_value_t = false)]
        once: bool,

        /// Show all device properties and extended info
        #[arg(short = 'V', long, default_value_t = false)]
        verbose: bool,

        /// Also show partition events (default: only whole disks)
        #[arg(long, default_value_t = false)]
        show_partitions: bool,
    },

    /// Watch for storage device insertions and removals, printing device info
    Watch {
        /// Only watch for this specific device (e.g. /dev/sdb)
        #[arg(short, long)]
        device: Option<String>,

        /// Only watch for this media type: usb, sd, ata, scsi, nvme
        #[arg(short, long)]
        media_type: Option<String>,

        /// Also show partition events (default: only whole disks)
        #[arg(long, default_value_t = false)]
        show_partitions: bool,

        /// Show all device properties and extended info
        #[arg(short, long, default_value_t = false)]
        verbose: bool,
    },
}

/// Aggregate key that uniquely identifies a physical device by its hardware
/// properties rather than its ephemeral device path.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DeviceKey {
    model: String,
    bus: String,
    serial: String,
}

impl std::fmt::Display for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}|{}|{}", self.model, self.bus, self.serial)
    }
}

/// Flash-specific settings. When present, the monitor loop will write images.
struct FlashConfig {
    image: PathBuf,
    image_hash: Option<String>,
    no_confirm: bool,
    skip_verify: bool,
    once: bool,
}

/// Shared settings for the monitor loop.
struct MonitorConfig {
    device: Option<String>,
    media_type: Option<String>,
    show_partitions: bool,
    verbose: bool,
    flash: Option<FlashConfig>,
}

const CHUNK_SIZE: usize = 256 * 1024; // 256K
const BUF_ALIGN: usize = 4096;
const MAX_RETRIES: u32 = 10;
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

// ── Job state machine ──────────────────────────────────────────────────

enum JobPhase {
    Writing,
    Verifying,
    Done { verified: Option<bool> },
    Failed,
}

struct WriteJob {
    // Write state
    src: Option<File>,
    dst: Option<File>,
    dev_path: PathBuf,
    dev_label: String,
    image_size: u64,
    written: u64,
    retries: u32,
    retry_after: Option<Instant>,
    skip_verify: bool,
    once: bool,

    /// true if the current dst fd is registered in epoll for EPOLLOUT.
    /// When true, we only write when epoll signals readiness.
    in_epoll: bool,

    // Pre-computed image hash for verification
    image_hash: Option<String>,

    // Phase
    phase: JobPhase,

    // Verify state (used during VerifyImage / VerifyDevice)
    verify_reader: Option<BufReader<File>>,
    verify_hasher: Option<Sha256>,
    verify_hashed: u64,
}

impl WriteJob {
    fn short_name(&self) -> &str {
        self.dev_label
            .strip_prefix("/dev/")
            .unwrap_or(&self.dev_label)
    }

    fn pct(&self) -> u64 {
        if self.image_size == 0 {
            return 100;
        }
        match self.phase {
            JobPhase::Writing => (self.written * 100) / self.image_size,
            JobPhase::Verifying => (self.verify_hashed * 100) / self.image_size,
            JobPhase::Done { .. } => 100,
            JobPhase::Failed => (self.written * 100) / self.image_size,
        }
    }

    fn phase_label(&self) -> &'static str {
        match self.phase {
            JobPhase::Writing if self.retry_after.is_some() => "retry",
            JobPhase::Writing => "write",
            JobPhase::Verifying => "verify",
            JobPhase::Done { .. } => "done",
            JobPhase::Failed => "FAIL",
        }
    }

    fn is_active(&self) -> bool {
        matches!(self.phase, JobPhase::Writing | JobPhase::Verifying)
    }
}

/// Open the output device with O_DIRECT | O_NONBLOCK (no O_SYNC — we
/// fdatasync at the end instead, so writes don't block forever on a
/// misbehaving device and the fd can participate in epoll).
fn open_output_device(path: &Path) -> Result<File, io::Error> {
    OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_DIRECT | libc::O_NONBLOCK)
        .open(path)
}

/// Allocate a page-aligned buffer for O_DIRECT I/O.
struct AlignedBuf {
    ptr: *mut u8,
    layout: std::alloc::Layout,
}

impl AlignedBuf {
    fn new(size: usize, align: usize) -> Result<Self, String> {
        let layout = std::alloc::Layout::from_size_align(size, align)
            .map_err(|e| format!("layout error: {}", e))?;
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err("failed to allocate aligned buffer".to_string());
        }
        Ok(Self { ptr, layout })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

// ── Status line ────────────────────────────────────────────────────────

/// Write to stderr and flush immediately.
fn eprint_flush(s: &str) {
    let mut err = io::stderr();
    let _ = err.write_all(s.as_bytes());
    let _ = err.flush();
}

/// Clear the status line on stderr (call before any log output).
fn clear_status() {
    eprint_flush("\r\x1b[K");
}

/// Print the single-line ANSI status showing all active jobs.
fn print_status(jobs: &HashMap<String, WriteJob>) {
    let mut parts: Vec<String> = Vec::new();
    // Sort by device name for stable ordering.
    let mut keys: Vec<&String> = jobs.keys().collect();
    keys.sort();
    for dev in keys {
        let job = &jobs[dev];
        if job.is_active() {
            parts.push(format!("{}: {} {}%", job.short_name(), job.phase_label(), job.pct()));
        }
    }
    if !parts.is_empty() {
        eprint_flush(&format!("\r\x1b[K{}", parts.join("  ")));
    }
}

// ── Main ───────────────────────────────────────────────────────────────

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let mut config = match args.command {
        Cmd::Flash {
            image,
            no_confirm,
            skip_verify,
            device,
            media_type,
            once,
            verbose,
            show_partitions,
        } => {
            if !image.exists() {
                error!("Image file does not exist: {}", image.display());
                std::process::exit(1);
            }

            let image_size = fs::metadata(&image)
                .expect("Failed to read image file metadata")
                .len();
            info!(
                "Watching for storage devices to flash with: {} ({:.2} MB)",
                image.display(),
                image_size as f64 / 1_048_576.0
            );

            if skip_verify {
                warn!("Post-write verification: DISABLED");
            }
            if no_confirm {
                warn!("Confirmation prompts: DISABLED — writes will proceed automatically!");
            }

            MonitorConfig {
                device,
                media_type,
                show_partitions,
                verbose,
                flash: Some(FlashConfig {
                    image,
                    image_hash: None, // computed in monitor() after udev socket is up
                    no_confirm,
                    skip_verify,
                    once,
                }),
            }
        }
        Cmd::Watch {
            device,
            media_type,
            show_partitions,
            verbose,
        } => {
            info!("Entering watch mode — monitoring block device events...");
            MonitorConfig {
                device,
                media_type,
                show_partitions,
                verbose,
                flash: None,
            }
        }
    };

    if let Some(ref dev) = config.device {
        info!("Filtering for device: {}", dev);
    }
    if let Some(ref mt) = config.media_type {
        info!("Filtering for media type: {}", mt);
    }

    if let Err(e) = monitor(&mut config) {
        error!("Fatal error: {}", e);
        std::process::exit(1);
    }
}

/// Enumerate all currently connected block devices (whole disks only).
/// Returns a set of DeviceKeys (model, bus, serial) to protect from writing.
fn enumerate_existing_devices() -> Result<HashSet<DeviceKey>, Box<dyn std::error::Error>> {
    let mut enumerator = udev::Enumerator::new()?;
    enumerator.match_subsystem("block")?;
    enumerator.match_property("DEVTYPE", "disk")?;

    let mut existing = HashSet::new();

    info!("Existing block devices (protected from writing):");

    for device in enumerator.scan_devices()? {
        let devnode = match device.devnode() {
            Some(d) => d.to_path_buf(),
            None => continue,
        };

        let dev_str = devnode.to_string_lossy().to_string();

        let get = |key: &str| -> String {
            device
                .property_value(key)
                .and_then(|v| v.to_str())
                .unwrap_or("unknown")
                .to_string()
        };

        let size_sectors = device
            .attribute_value("size")
            .and_then(|v| v.to_string_lossy().parse::<u64>().ok());

        // Skip zero-size devices (empty card reader slots)
        if size_sectors.unwrap_or(0) == 0 {
            continue;
        }

        let size_str = format_size_from_sectors(size_sectors);

        let key = DeviceKey {
            model: get("ID_MODEL"),
            bus: get("ID_BUS"),
            serial: get("ID_SERIAL_SHORT"),
        };

        info!(
            "  {} — {} {} [{}] ({}) key={}",
            dev_str,
            get("ID_VENDOR"),
            key.model,
            key.bus,
            size_str,
            key,
        );

        existing.insert(key);
    }

    if existing.is_empty() {
        info!("  (none found)");
    }

    Ok(existing)
}

// ── epoll helpers ──────────────────────────────────────────────────────

fn epoll_create() -> Result<RawFd, io::Error> {
    let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn epoll_add(epfd: RawFd, fd: RawFd, events: u32, data: u64) -> Result<(), io::Error> {
    let mut ev = libc::epoll_event {
        events,
        u64: data,
    };
    let ret = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn epoll_del(epfd: RawFd, fd: RawFd) {
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
}

/// Try to register a write fd in epoll. Returns true on success.
fn epoll_try_add_write(epfd: RawFd, fd: RawFd) -> bool {
    epoll_add(epfd, fd, libc::EPOLLOUT as u32, fd as u64).is_ok()
}

// ── The main event loop ────────────────────────────────────────────────

const UDEV_TOKEN: u64 = u64::MAX;

fn monitor(config: &mut MonitorConfig) -> Result<(), Box<dyn std::error::Error>> {
    let protected = enumerate_existing_devices()?;

    let socket = udev::MonitorBuilder::new()?
        .match_subsystem("block")?
        .listen()?;

    // Compute image hash now — udev socket is already listening, so any
    // device insertions during hashing will be queued and picked up on
    // the first loop iteration.
    if let Some(ref mut flash) = config.flash {
        if !flash.skip_verify {
            info!("Computing SHA-256 of image...");
            let hash = hash_file(&flash.image)?;
            info!("Image hash: {}", hash);
            flash.image_hash = Some(hash);
        }
    }

    let udev_fd = socket.as_raw_fd();

    let mut seen_diskseq: HashMap<String, String> = HashMap::new();
    let mut reported_devices: HashSet<String> = HashSet::new();
    let mut jobs: HashMap<String, WriteJob> = HashMap::new();
    let mut fd_to_dev: HashMap<RawFd, String> = HashMap::new();

    let mut buf = AlignedBuf::new(CHUNK_SIZE, BUF_ALIGN)
        .map_err(|e| format!("buffer alloc failed: {}", e))?;

    let epfd = epoll_create()?;
    epoll_add(epfd, udev_fd, libc::EPOLLIN as u32, UDEV_TOKEN)?;

    info!("Listening for udev block device events... (Ctrl+C to quit)");

    let mut events: [libc::epoll_event; 64] = [libc::epoll_event { events: 0, u64: 0 }; 64];

    loop {
        let has_active = jobs.values().any(|j| j.is_active());
        // If any active write jobs are NOT in epoll, use timeout 0 so we
        // don't stall them waiting for unrelated epoll events.
        // If all writers are in epoll, we can block until something fires.
        let any_writers_outside_epoll = jobs.values().any(|j| {
            matches!(j.phase, JobPhase::Writing) && j.dst.is_some() && !j.in_epoll
        });
        let any_verifying = jobs.values().any(|j| matches!(j.phase, JobPhase::Verifying));
        let timeout_ms = if any_writers_outside_epoll || any_verifying {
            0
        } else if has_active {
            100 // writers in epoll or retry timers
        } else {
            200
        };

        let nfds = unsafe {
            libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, timeout_ms)
        };

        if nfds < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }

        // Collect which write fds are ready and whether we got a udev event.
        let mut got_udev = false;
        let mut ready_fds: HashSet<RawFd> = HashSet::new();
        for i in 0..nfds as usize {
            if events[i].u64 == UDEV_TOKEN {
                got_udev = true;
            } else {
                ready_fds.insert(events[i].u64 as RawFd);
            }
        }

        // ── drain udev events (clear status first since these log) ────
        if got_udev {
            clear_status();
            handle_udev_events(
                &socket,
                config,
                &protected,
                &mut seen_diskseq,
                &mut reported_devices,
                &mut jobs,
                &mut fd_to_dev,
                epfd,
            )?;
        }

        // ── pump one chunk per active job ──────────────────────────────
        let active: Vec<String> = jobs
            .iter()
            .filter(|(_, j)| j.is_active())
            .map(|(k, _)| k.clone())
            .collect();
        for dev in active {
            if let Some(job) = jobs.get_mut(&dev) {
                match job.phase {
                    JobPhase::Writing => {
                        // If the fd is in epoll, only write when epoll
                        // says the device is ready.
                        if job.in_epoll {
                            if let Some(ref dst) = job.dst {
                                if !ready_fds.contains(&dst.as_raw_fd()) {
                                    continue;
                                }
                            }
                        }
                        do_write_chunk(job, buf.as_mut_slice(), &mut fd_to_dev);
                    }
                    JobPhase::Verifying => do_verify_chunk(job, buf.as_mut_slice()),
                    _ => {}
                }
            }
        }

        // ── service retry timers & reap finished jobs ──────────────────
        let needs_reap = jobs.values().any(|j| {
            matches!(j.phase, JobPhase::Done { .. } | JobPhase::Failed)
        });
        if needs_reap {
            clear_status();
        }
        service_retries_and_reap(&mut jobs, &mut fd_to_dev, epfd)?;

        // ── redraw status line ─────────────────────────────────────────
        if jobs.values().any(|j| j.is_active()) {
            print_status(&jobs);
        }
    }
}

/// Drain all pending udev events from the socket and create WriteJobs for
/// newly-inserted devices (if we're in flash mode).
fn handle_udev_events(
    socket: &udev::MonitorSocket,
    config: &MonitorConfig,
    protected: &HashSet<DeviceKey>,
    seen_diskseq: &mut HashMap<String, String>,
    reported_devices: &mut HashSet<String>,
    jobs: &mut HashMap<String, WriteJob>,
    fd_to_dev: &mut HashMap<RawFd, String>,
    epfd: RawFd,
) -> Result<(), Box<dyn std::error::Error>> {
    for event in socket.iter() {
        let event_type = event.event_type();

        let devnode = match event.devnode() {
            Some(d) => d.to_path_buf(),
            None => continue,
        };

        let devtype = event
            .property_value("DEVTYPE")
            .and_then(|v| v.to_str())
            .unwrap_or("");

        if devtype != "disk" && !config.show_partitions {
            continue;
        }

        let dev_str = devnode.to_string_lossy().to_string();

        let diskseq = event
            .property_value("DISKSEQ")
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .to_string();

        let is_udev_removal = event_type == udev::EventType::Remove;

        if !diskseq.is_empty() {
            if is_udev_removal {
                seen_diskseq.remove(&dev_str);
            } else if let Some(prev) = seen_diskseq.get(&dev_str) {
                if *prev == diskseq {
                    continue;
                }
            }

            if !is_udev_removal {
                seen_diskseq.insert(dev_str.clone(), diskseq);
            }
        }

        let device_size_sectors = event
            .attribute_value("size")
            .and_then(|v| v.to_string_lossy().parse::<u64>().ok())
            .unwrap_or(0);

        let event_label = if is_udev_removal {
            "REMOVED"
        } else if event_type == udev::EventType::Add {
            "INSERTED"
        } else {
            let media_change = event
                .property_value("DISK_MEDIA_CHANGE")
                .and_then(|v| v.to_str())
                .unwrap_or("0");
            if media_change == "1" {
                if device_size_sectors > 0 {
                    "INSERTED"
                } else {
                    "REMOVED"
                }
            } else {
                "CHANGED"
            }
        };

        let is_removal = is_udev_removal || event_label == "REMOVED";

        if device_size_sectors == 0 && !is_removal {
            continue;
        }
        if is_removal {
            if let Some(job) = jobs.remove(&dev_str) {
                if let Some(ref dst) = job.dst {
                    let fd = dst.as_raw_fd();
                    if job.in_epoll {
                        epoll_del(epfd, fd);
                    }
                    fd_to_dev.remove(&fd);
                }
                info!("{}: removed, aborting", dev_str);
            }
            if !reported_devices.remove(&dev_str) {
                continue;
            }
        }
        if !is_removal && reported_devices.contains(&dev_str) {
            continue;
        }

        if let Some(ref target_dev) = config.device {
            if dev_str != *target_dev {
                continue;
            }
        }

        if let Some(ref target_type) = config.media_type {
            if !is_removal && !matches_media_type(&event, target_type) {
                continue;
            }
        }

        let type_label = if devtype == "partition" {
            "partition"
        } else {
            "disk"
        };

        let event_key = {
            let get = |key: &str| -> String {
                event
                    .property_value(key)
                    .and_then(|v| v.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            };
            DeviceKey {
                model: get("ID_MODEL"),
                bus: get("ID_BUS"),
                serial: get("ID_SERIAL_SHORT"),
            }
        };

        let is_protected = protected.contains(&event_key);

        if !is_removal {
            reported_devices.insert(dev_str.clone());
        }

        if is_removal {
            info!("--- {} {} ---", event_label, dev_str);
        } else if is_protected {
            info!(
                "--- {} {} ({}) [PROTECTED] ---",
                event_label, dev_str, type_label
            );
        } else {
            info!("--- {} {} ({}) ---", event_label, dev_str, type_label);
        }

        if !is_removal {
            if config.verbose {
                log_device_info_verbose(&event);
            } else {
                log_device_info_brief(&event);
            }
        }

        // Flash logic
        if let Some(ref flash) = config.flash {
            if is_removal || is_protected {
                if is_protected && !is_removal {
                    warn!(
                        "  REFUSING to write to {} — device was present at startup!",
                        dev_str
                    );
                }
                continue;
            }

            if jobs.contains_key(&dev_str) {
                info!("  Already flashing {}, skipping", dev_str);
                continue;
            }

            if !flash.no_confirm {
                print!(
                    "\nWrite {} to {}? [y/N]: ",
                    flash.image.display(),
                    dev_str
                );
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().lock().read_line(&mut input)?;

                if !input.trim().eq_ignore_ascii_case("y") {
                    info!("Skipped writing to {}", dev_str);
                    continue;
                }
            }

            let image_size = fs::metadata(&flash.image)?.len();
            info!("Writing -> {}", dev_str);

            let src = File::open(&flash.image)?;
            let dst = match open_output_device(&devnode) {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to open {} for writing: {}", dev_str, e);
                    continue;
                }
            };

            let dst_fd = dst.as_raw_fd();
            let in_epoll = epoll_try_add_write(epfd, dst_fd);
            if in_epoll {
                fd_to_dev.insert(dst_fd, dev_str.clone());
            }

            jobs.insert(
                dev_str.clone(),
                WriteJob {
                    src: Some(src),
                    dst: Some(dst),
                    dev_path: devnode.clone(),
                    dev_label: dev_str.clone(),
                    image_size,
                    written: 0,
                    retries: 0,
                    retry_after: None,
                    skip_verify: flash.skip_verify,
                    once: flash.once,
                    in_epoll,
                    image_hash: flash.image_hash.clone(),
                    phase: JobPhase::Writing,
                    verify_reader: None,
                    verify_hasher: None,
                    verify_hashed: 0,
                },
            );
        }
    }
    Ok(())
}

// ── Write chunk ────────────────────────────────────────────────────────

fn do_write_chunk(job: &mut WriteJob, buf: &mut [u8], fd_to_dev: &mut HashMap<RawFd, String>) {
    if job.dst.is_none() {
        return;
    }

    let src = match job.src.as_mut() {
        Some(s) => s,
        None => return,
    };

    let n = match src.read(buf) {
        Ok(0) => return, // EOF — reap will transition phase
        Ok(n) => n,
        Err(_) => {
            job.retries = MAX_RETRIES + 1;
            job.phase = JobPhase::Failed;
            return;
        }
    };

    // O_DIRECT needs sector-aligned write sizes. Pad the last chunk.
    let write_len = if n % 512 != 0 {
        let padded = (n + 511) & !511;
        for b in &mut buf[n..padded] {
            *b = 0;
        }
        padded
    } else {
        n
    };

    let dst = job.dst.as_mut().unwrap();
    match dst.write_all(&buf[..write_len]) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            // Device not ready — rewind source, try again next iteration.
            let _ = src.seek(SeekFrom::Start(job.written));
            return;
        }
        Err(_) => {
            job.retries += 1;
            if job.retries > MAX_RETRIES {
                job.phase = JobPhase::Failed;
                return;
            }
            // Clean up fd tracking before dropping dst (fd close auto-removes from epoll).
            if let Some(ref dst) = job.dst {
                fd_to_dev.remove(&dst.as_raw_fd());
            }
            job.dst = None;
            job.in_epoll = false;
            job.retry_after = Some(Instant::now() + RETRY_DELAY);
            let _ = src.seek(SeekFrom::Start(job.written));
            return;
        }
    }

    job.written += n as u64;
}

// ── Verify chunk ───────────────────────────────────────────────────────

fn do_verify_chunk(job: &mut WriteJob, buf: &mut [u8]) {
    let reader = match job.verify_reader.as_mut() {
        Some(r) => r,
        None => return,
    };
    let hasher = match job.verify_hasher.as_mut() {
        Some(h) => h,
        None => return,
    };

    let remaining = job.image_size - job.verify_hashed;
    if remaining == 0 {
        return; // reap will handle phase transition
    }

    let to_read = (buf.len() as u64).min(remaining) as usize;
    match reader.read(&mut buf[..to_read]) {
        Ok(0) => {} // EOF — reap handles it
        Ok(n) => {
            hasher.update(&buf[..n]);
            job.verify_hashed += n as u64;
        }
        Err(_) => {
            job.phase = JobPhase::Failed;
        }
    }
}

// ── Service retries & reap ─────────────────────────────────────────────

fn service_retries_and_reap(
    jobs: &mut HashMap<String, WriteJob>,
    fd_to_dev: &mut HashMap<RawFd, String>,
    epfd: RawFd,
) -> Result<(), Box<dyn std::error::Error>> {
    // Phase transitions for active jobs.
    let keys: Vec<String> = jobs.keys().cloned().collect();
    for dev in &keys {
        let job = jobs.get_mut(dev).unwrap();

        match job.phase {
            JobPhase::Writing => {
                // Retry timer: reopen device after delay.
                if job.dst.is_none() {
                    if let Some(deadline) = job.retry_after {
                        if Instant::now() >= deadline {
                            job.retry_after = None;
                            match open_output_device(&job.dev_path) {
                                Ok(mut dst) => {
                                    if dst.seek(SeekFrom::Start(job.written)).is_err() {
                                        job.retries = MAX_RETRIES + 1;
                                        job.phase = JobPhase::Failed;
                                        continue;
                                    }
                                    let new_fd = dst.as_raw_fd();
                                    let ok = epoll_try_add_write(epfd, new_fd);
                                    if ok {
                                        fd_to_dev.insert(new_fd, dev.clone());
                                    }
                                    job.in_epoll = ok;
                                    job.dst = Some(dst);
                                }
                                Err(_) => {
                                    job.retries += 1;
                                    if job.retries > MAX_RETRIES {
                                        job.phase = JobPhase::Failed;
                                    } else {
                                        job.retry_after =
                                            Some(Instant::now() + RETRY_DELAY);
                                    }
                                }
                            }
                        }
                    }
                }

                // Write complete → fdatasync, then verify or done.
                if job.written >= job.image_size {
                    // Flush to physical media before closing.
                    if let Some(ref dst) = job.dst {
                        let fd = dst.as_raw_fd();
                        if job.in_epoll {
                            epoll_del(epfd, fd);
                        }
                        fd_to_dev.remove(&fd);
                        // fdatasync to ensure data is on the device.
                        unsafe { libc::fdatasync(fd) };
                    }
                    job.src = None;
                    job.dst = None;
                    job.in_epoll = false;
                    if job.skip_verify || job.image_hash.is_none() {
                        job.phase = JobPhase::Done { verified: None };
                    } else {
                        match File::open(&job.dev_path) {
                            Ok(f) => {
                                job.verify_reader =
                                    Some(BufReader::with_capacity(1024 * 1024, f));
                                job.verify_hasher = Some(Sha256::new());
                                job.verify_hashed = 0;
                                job.phase = JobPhase::Verifying;
                            }
                            Err(_) => {
                                job.phase = JobPhase::Failed;
                            }
                        }
                    }
                }
            }

            JobPhase::Verifying => {
                if job.verify_hashed >= job.image_size {
                    let hasher = job.verify_hasher.take().unwrap();
                    let device_hash = format!("{:x}", hasher.finalize());
                    let matched = job.image_hash.as_deref() == Some(device_hash.as_str());
                    job.verify_reader = None;
                    job.phase = JobPhase::Done {
                        verified: Some(matched),
                    };
                }
            }

            _ => {}
        }
    }

    // Reap completed / failed jobs.
    let mut to_remove: Vec<String> = Vec::new();
    for (dev, job) in jobs.iter() {
        match job.phase {
            JobPhase::Done { .. } | JobPhase::Failed => {
                to_remove.push(dev.clone());
            }
            _ => {}
        }
    }

    for dev in to_remove {
        let job = jobs.remove(&dev).unwrap();
        // Clean up epoll if dst is still open (e.g. Failed with dst intact).
        if let Some(ref dst) = job.dst {
            let fd = dst.as_raw_fd();
            if job.in_epoll {
                epoll_del(epfd, fd);
            }
            fd_to_dev.remove(&fd);
        }
        match job.phase {
            JobPhase::Done { verified } => {
                clear_status();
                match verified {
                    None => info!("{}: done (no verify)", dev),
                    Some(true) => info!("{}: done, verification PASSED", dev),
                    Some(false) => {
                        error!("{}: done, verification FAILED — checksums do not match!", dev)
                    }
                }
                if job.once {
                    info!("--once flag set, exiting after first successful write.");
                    std::process::exit(0);
                }
            }
            JobPhase::Failed => {
                clear_status();
                error!("{}: write failed", dev);
            }
            _ => {}
        }
    }

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────

fn hash_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let file_size = fs::metadata(path)?.len();
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut hashed: u64 = 0;
    let mut last_pct: u64 = u64::MAX;

    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let n = buf.len();
        hasher.update(&buf[..n]);
        reader.consume(n);
        hashed += n as u64;

        if file_size > 0 {
            let pct = (hashed * 100) / file_size;
            if pct != last_pct {
                eprint_flush(&format!("\r\x1b[Khashing: {}%", pct));
                last_pct = pct;
            }
        }
    }

    clear_status();
    Ok(format!("{:x}", hasher.finalize()))
}

fn format_size_from_sectors(sectors: Option<u64>) -> String {
    match sectors {
        Some(s) => {
            let bytes = s * 512;
            if bytes >= 1_073_741_824 {
                format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
            } else {
                format!("{:.2} MB", bytes as f64 / 1_048_576.0)
            }
        }
        None => "unknown".to_string(),
    }
}

fn matches_media_type(event: &udev::Event, target: &str) -> bool {
    let id_bus = event
        .property_value("ID_BUS")
        .and_then(|v| v.to_str())
        .unwrap_or("");

    let id_type = event
        .property_value("ID_TYPE")
        .and_then(|v| v.to_str())
        .unwrap_or("");

    let id_drive = event
        .property_value("ID_DRIVE_FLASH_SD")
        .and_then(|v| v.to_str())
        .unwrap_or("0");

    let id_path = event
        .property_value("ID_PATH")
        .and_then(|v| v.to_str())
        .unwrap_or("");

    match target.to_lowercase().as_str() {
        "usb" => id_bus == "usb",
        "sd" => id_drive == "1" || id_bus == "usb" && id_type == "disk",
        "ata" | "sata" => id_bus == "ata",
        "scsi" => id_bus == "scsi",
        "nvme" => id_path.contains("nvme"),
        other => {
            // Fall back to substring match on ID_BUS
            id_bus == other
        }
    }
}

fn log_device_info_brief(event: &udev::Event) {
    let get = |key: &str| -> String {
        event
            .property_value(key)
            .and_then(|v| v.to_str())
            .unwrap_or("unknown")
            .to_string()
    };

    info!("  Vendor: {}", get("ID_VENDOR"));
    info!("  Model:  {}", get("ID_MODEL"));
    info!("  Serial: {}", get("ID_SERIAL_SHORT"));
    info!("  Bus:    {}", get("ID_BUS"));

    let size = format_size_from_sectors(
        event
            .attribute_value("size")
            .and_then(|v| v.to_string_lossy().parse::<u64>().ok()),
    );
    info!("  Size:   {}", size);
}

fn log_device_info_verbose(event: &udev::Event) {
    let get = |key: &str| -> String {
        event
            .property_value(key)
            .and_then(|v| v.to_str())
            .unwrap_or("unknown")
            .to_string()
    };

    info!("  Vendor:      {}", get("ID_VENDOR"));
    info!("  Model:       {}", get("ID_MODEL"));
    info!("  Bus:         {}", get("ID_BUS"));
    info!("  Serial:      {}", get("ID_SERIAL_SHORT"));
    info!("  Dev type:    {}", get("DEVTYPE"));
    info!("  FS type:     {}", get("ID_FS_TYPE"));
    info!("  FS label:    {}", get("ID_FS_LABEL"));
    info!("  FS UUID:     {}", get("ID_FS_UUID"));
    info!("  Part scheme: {}", get("ID_PART_TABLE_TYPE"));

    let size = format_size_from_sectors(
        event
            .attribute_value("size")
            .and_then(|v| v.to_string_lossy().parse::<u64>().ok()),
    );
    info!("  Size:        {}", size);

    // Dump all properties for maximum visibility
    let props: Vec<_> = event.properties().collect();
    if !props.is_empty() {
        info!("  All properties:");
        for prop in props {
            info!(
                "    {}={}",
                prop.name().to_string_lossy(),
                prop.value().to_string_lossy()
            );
        }
    }
}
