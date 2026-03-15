use clap::{Parser, Subcommand};
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// Monitors udev for storage media insertions and automatically writes an image using dd.
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

        /// Block size for dd (default: 256M)
        #[arg(long, default_value = "256M")]
        bs: String,

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
    no_confirm: bool,
    skip_verify: bool,
    bs: String,
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

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let config = match args.command {
        Cmd::Flash {
            image,
            no_confirm,
            skip_verify,
            device,
            media_type,
            bs,
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
                    no_confirm,
                    skip_verify,
                    bs,
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

    if let Err(e) = monitor(&config) {
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

fn monitor(config: &MonitorConfig) -> Result<(), Box<dyn std::error::Error>> {
    let protected = enumerate_existing_devices()?;

    let socket = udev::MonitorBuilder::new()?
        .match_subsystem("block")?
        .listen()?;

    // Track last seen DISKSEQ per device to deduplicate events.
    // USB card readers fire two CHANGED events for a single media insertion
    // (DISK_MEDIA_CHANGE then SYNTH_UUID re-probe) — same DISKSEQ, sequential SEQNUMs.
    let mut seen_diskseq: HashMap<String, String> = HashMap::new();
    // Track devices we've actually shown to the user, so we only print
    // removal events for devices we previously reported.
    let mut reported_devices: HashSet<String> = HashSet::new();

    // Shared state for concurrent flash operations.
    // Devices currently being flashed — prevents double-writes if events repeat.
    let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    // Signal for --once: any thread that finishes successfully sets this.
    let done = Arc::new(AtomicBool::new(false));

    info!("Listening for udev block device events... (Ctrl+C to quit)");

    loop {
        if done.load(Ordering::SeqCst) {
            info!("--once flag set, exiting after first successful write.");
            return Ok(());
        }

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

            // Filter partitions unless --show-partitions
            if devtype != "disk" && !config.show_partitions {
                continue;
            }

            let dev_str = devnode.to_string_lossy().to_string();

            // Deduplicate by DISKSEQ — skip if we already reported this exact
            // disk sequence for this device
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

            // Determine the user-facing event label.
            // DISK_MEDIA_CHANGE=1 fires for both insert and removal on card readers,
            // so check the device size: 0 means media was removed, >0 means inserted.
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

            // Skip zero-size devices (empty card reader slots).
            if device_size_sectors == 0 && !is_removal {
                continue;
            }
            // Only show removals for devices we previously reported.
            if is_removal && !reported_devices.remove(&dev_str) {
                continue;
            }
            // Only report one insertion per device — skip if already reported.
            if !is_removal && reported_devices.contains(&dev_str) {
                continue;
            }

            // Device name filter
            if let Some(ref target_dev) = config.device {
                if dev_str != *target_dev {
                    continue;
                }
            }

            // Media type filter (only useful on add/change — remove events lack properties)
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

            // Track that we reported this device so we show its removal later
            if !is_removal {
                reported_devices.insert(dev_str.clone());
            }

            // Print event header
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

            // Print device details (nothing useful on removal)
            if !is_removal {
                if config.verbose {
                    log_device_info_verbose(&event);
                } else {
                    log_device_info_brief(&event);
                }
            }

            // Flash logic — only if we have flash config, device was inserted, and not protected
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

                // Skip if another thread is already writing to this device
                {
                    let mut flight = in_flight.lock().unwrap();
                    if !flight.insert(dev_str.clone()) {
                        info!("  Already flashing {}, skipping", dev_str);
                        continue;
                    }
                }

                // Confirmation — handled here in the main loop, not in the thread
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
                        in_flight.lock().unwrap().remove(&dev_str);
                        continue;
                    }
                }

                let image = flash.image.clone();
                let skip_verify = flash.skip_verify;
                let bs = flash.bs.clone();
                let once = flash.once;
                let devnode = devnode.clone();
                let dev_str = dev_str.clone();
                let in_flight = Arc::clone(&in_flight);
                let done = Arc::clone(&done);

                thread::spawn(move || {
                    let _cleanup = InFlightGuard {
                        in_flight: Arc::clone(&in_flight),
                        dev: dev_str.clone(),
                    };

                    // Do the write
                    match flash_device(&image, &devnode, &bs) {
                        Ok(()) => {
                            info!("Successfully wrote image to {}", dev_str);
                        }
                        Err(e) => {
                            error!("Failed to write to {}: {}", dev_str, e);
                            return;
                        }
                    }

                    if !skip_verify {
                        info!("Verifying written image on {}...", dev_str);
                        match verify_image(&image, &devnode) {
                            Ok(true) => info!("Verification PASSED for {}", dev_str),
                            Ok(false) => {
                                error!(
                                    "Verification FAILED for {} — checksums do not match!",
                                    dev_str
                                )
                            }
                            Err(e) => error!("Verification error for {}: {}", dev_str, e),
                        }
                    }

                    if once {
                        done.store(true, Ordering::SeqCst);
                    }
                });
            }

            // Check if a --once thread signaled completion
            if done.load(Ordering::SeqCst) {
                info!("--once flag set, exiting after first successful write.");
                return Ok(());
            }
        }
    }
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

/// Page-aligned buffer for O_DIRECT I/O.
struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: The buffer is exclusively owned and not shared.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    fn new(len: usize, align: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut ptr: *mut libc::c_void = std::ptr::null_mut();
        let ret = unsafe { libc::posix_memalign(&mut ptr, align, len) };
        if ret != 0 {
            return Err(format!("posix_memalign failed: {}", ret).into());
        }
        // Zero-initialize
        unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, len) };
        Ok(Self {
            ptr: ptr as *mut u8,
            len,
        })
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe { libc::free(self.ptr as *mut libc::c_void) };
    }
}

impl std::ops::Deref for AlignedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl std::ops::DerefMut for AlignedBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

/// RAII guard that removes a device from the in-flight set when dropped,
/// ensuring cleanup even if the flash thread panics.
struct InFlightGuard {
    in_flight: Arc<Mutex<HashSet<String>>>,
    dev: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.in_flight.lock().unwrap().remove(&self.dev);
    }
}

/// Parse a human-readable block size string (e.g. "256M", "4K", "1G", "512") into bytes.
fn parse_block_size(bs: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let bs = bs.trim();
    let (num_str, multiplier) = match bs.as_bytes().last() {
        Some(b'K' | b'k') => (&bs[..bs.len() - 1], 1024usize),
        Some(b'M' | b'm') => (&bs[..bs.len() - 1], 1024 * 1024),
        Some(b'G' | b'g') => (&bs[..bs.len() - 1], 1024 * 1024 * 1024),
        _ => (bs, 1),
    };
    let n: usize = num_str
        .parse()
        .map_err(|_| format!("invalid block size: {}", bs))?;
    Ok(n * multiplier)
}

/// Query the kernel for O_DIRECT alignment requirements via statx(STATX_DIOALIGN).
/// Returns (mem_align, offset_align) in bytes.
fn dio_alignment(path: &Path) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())?;

    // SAFETY: zeroed statx is valid for the syscall to fill in.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };

    const STATX_DIOALIGN: libc::c_uint = 0x2000;

    let ret = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            0,
            STATX_DIOALIGN,
            &mut stx,
        )
    };
    if ret != 0 {
        return Err(format!(
            "statx({}) failed: {}",
            path.display(),
            io::Error::last_os_error()
        )
        .into());
    }

    if stx.stx_mask & STATX_DIOALIGN == 0 {
        return Err(format!(
            "kernel did not return DIOALIGN for {}",
            path.display()
        )
        .into());
    }

    let mem_align = stx.stx_dio_mem_align as usize;
    let offset_align = stx.stx_dio_offset_align as usize;

    if mem_align == 0 || offset_align == 0 {
        return Err(format!(
            "device {} does not support O_DIRECT (alignment is 0)",
            path.display()
        )
        .into());
    }

    Ok((mem_align, offset_align))
}

/// Write a buffer to a file descriptor at an explicit offset using pwrite(2).
/// Handles partial writes while maintaining O_DIRECT alignment: if a short write
/// lands on a mem_align boundary we continue from there; otherwise we copy the
/// remainder into a fresh aligned bounce buffer and retry.
fn aligned_pwrite(fd: i32, buf: &[u8], mut offset: u64, mem_align: usize) -> io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        let ptr = buf[pos..].as_ptr();
        let len = buf.len() - pos;
        let n = unsafe {
            libc::pwrite(
                fd,
                ptr as *const libc::c_void,
                len,
                offset as libc::off_t,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let n = n as usize;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "pwrite returned 0",
            ));
        }
        pos += n;
        offset += n as u64;

        // If there's remaining data and the new buffer pointer isn't aligned,
        // bounce the remainder through a fresh aligned allocation.
        if pos < buf.len() && (buf[pos..].as_ptr() as usize) % mem_align != 0 {
            let remaining = &buf[pos..];
            let bounce = AlignedBuf::new(remaining.len(), mem_align).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            })?;
            // SAFETY: we just allocated bounce with len == remaining.len()
            unsafe {
                std::ptr::copy_nonoverlapping(
                    remaining.as_ptr(),
                    bounce.ptr,
                    remaining.len(),
                );
            }
            return aligned_pwrite(fd, &bounce, offset, mem_align);
        }
    }
    Ok(())
}

fn flash_device(image: &Path, device: &Path, bs: &str) -> Result<(), Box<dyn std::error::Error>> {
    let block_size = parse_block_size(bs)?;
    let image_size = fs::metadata(image)?.len();
    let dev_str = device.to_string_lossy();

    let (mem_align, offset_align) = dio_alignment(device)?;
    info!(
        "[{}] O_DIRECT alignment: mem={} bytes, offset={} bytes",
        dev_str, mem_align, offset_align
    );

    // Round block_size down to a multiple of offset_align for O_DIRECT writes
    let block_size = (block_size / offset_align) * offset_align;
    if block_size == 0 {
        return Err(format!(
            "block size is smaller than device offset alignment ({} bytes)",
            offset_align
        )
        .into());
    }

    info!(
        "Writing {} ({} bytes) -> {} (bs={})",
        image.display(),
        image_size,
        dev_str,
        bs
    );

    let mut src = BufReader::with_capacity(block_size, File::open(image)?);
    let dst = fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_SYNC | libc::O_DIRECT)
        .open(device)?;
    let fd = dst.as_raw_fd();
    let mut file_offset: u64 = 0;
    let mut written: u64 = 0;
    let mut buf = AlignedBuf::new(block_size, mem_align)?;
    let mut next_pct: u64 = 10;

    loop {
        let mut filled = 0;
        // Fill the buffer completely (or until EOF)
        while filled < block_size {
            let n = src.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }

        // O_DIRECT requires writes to be a multiple of offset_align.
        // Pad the final chunk with zeros.
        let mask = offset_align - 1;
        let write_len = (filled + mask) & !mask;
        if write_len > filled {
            buf[filled..write_len].fill(0);
        }
        aligned_pwrite(fd, &buf[..write_len], file_offset, mem_align)?;
        file_offset += write_len as u64;
        written += filled as u64;

        let pct = if image_size > 0 {
            written * 100 / image_size
        } else {
            100
        };
        if pct >= next_pct {
            info!("[{}] {}% ({:.1} MB / {:.1} MB)", dev_str, next_pct,
                written as f64 / 1_048_576.0,
                image_size as f64 / 1_048_576.0,
            );
            next_pct += 10;
        }
    }

    drop(dst);

    info!("[{}] Write complete: {} bytes written", dev_str, written);
    Ok(())
}

fn verify_image(image: &Path, device: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let image_size = fs::metadata(image)?.len();

    info!("Computing SHA-256 of image ({} bytes)...", image_size);
    let image_hash = hash_file(image, None)?;
    info!("Image hash:  {}", image_hash);

    info!(
        "Computing SHA-256 of device (first {} bytes)...",
        image_size
    );
    let device_hash = hash_file(device, Some(image_size))?;
    info!("Device hash: {}", device_hash);

    Ok(image_hash == device_hash)
}

fn hash_file(path: &Path, limit: Option<u64>) -> Result<String, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();

    let mut remaining = limit.unwrap_or(u64::MAX);
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let to_read = (buf.len() as u64).min(remaining) as usize;
        hasher.update(&buf[..to_read]);
        reader.consume(to_read);
        remaining -= to_read as u64;
        if remaining == 0 {
            break;
        }
    }

    Ok(format!("{:x}", hasher.finalize()))
}
