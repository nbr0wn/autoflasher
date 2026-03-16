use clap::{Parser, Subcommand};
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read as _, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

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

/// A write thread flashing an image to a device.
struct InFlightOp {
    handle: JoinHandle<Result<(), String>>,
    devnode: PathBuf,
    image: PathBuf,
    skip_verify: bool,
    once: bool,
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

/// Reap finished write threads: log results and run verification.
fn reap_children(in_flight: &mut HashMap<String, InFlightOp>) -> bool {
    let mut finished: Vec<String> = Vec::new();
    let mut got_once = false;

    for (dev, op) in in_flight.iter_mut() {
        if !op.handle.is_finished() {
            continue;
        }
        finished.push(dev.clone());
    }

    for dev in &finished {
        let op = in_flight.remove(dev).unwrap();
        match op.handle.join() {
            Ok(Ok(())) => {
                info!("Successfully wrote image to {}", dev);

                if !op.skip_verify {
                    info!("Verifying written image on {}...", dev);
                    match verify_image(&op.image, &op.devnode) {
                        Ok(true) => info!("Verification PASSED for {}", dev),
                        Ok(false) => {
                            error!(
                                "Verification FAILED for {} — checksums do not match!",
                                dev
                            )
                        }
                        Err(e) => error!("Verification error for {}: {}", dev, e),
                    }
                }

                if op.once {
                    got_once = true;
                }
            }
            Ok(Err(e)) => {
                error!("Failed to write to {}: {}", dev, e);
            }
            Err(_) => {
                error!("Write thread for {} panicked!", dev);
            }
        }
    }

    got_once
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

    // Running dd child processes, keyed by device path.
    let mut in_flight: HashMap<String, InFlightOp> = HashMap::new();

    info!("Listening for udev block device events... (Ctrl+C to quit)");

    // The udev MonitorSocket is non-blocking, so socket.iter() returns None
    // immediately when there are no pending events. Use poll() to sleep until
    // the kernel actually delivers an event, instead of busy-spinning.
    let socket_fd = socket.as_raw_fd();

    loop {
        // Reap any finished dd processes
        if reap_children(&mut in_flight) {
            info!("--once flag set, exiting after first successful write.");
            return Ok(());
        }

        // Block until the socket has data (or 1s timeout to reap children)
        let mut pfd = libc::pollfd {
            fd: socket_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if ret <= 0 {
            continue;
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

                // Skip if dd is already writing to this device
                if in_flight.contains_key(&dev_str) {
                    info!("  Already flashing {}, skipping", dev_str);
                    continue;
                }

                // Confirmation
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
                info!(
                    "Writing {} ({} bytes) -> {}",
                    flash.image.display(),
                    image_size,
                    dev_str,
                );

                let thread_image = flash.image.clone();
                let thread_dev = devnode.clone();
                let thread_dev_str = dev_str.clone();
                let handle = thread::spawn(move || {
                    write_image(&thread_image, &thread_dev, &thread_dev_str)
                });

                in_flight.insert(
                    dev_str.clone(),
                    InFlightOp {
                        handle,
                        devnode: devnode.clone(),
                        image: flash.image.clone(),
                        skip_verify: flash.skip_verify,
                        once: flash.once,
                    },
                );
            }
        }
    }
}

const CHUNK_SIZE: usize = 16 * 1024; // 16K
const MAX_RETRIES: u32 = 10;
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// Open the output device with O_DIRECT | O_SYNC.
fn open_output_device(path: &Path) -> Result<File, io::Error> {
    OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_DIRECT | libc::O_SYNC)
        .open(path)
}

/// Write an image file to a device in 16K chunks.
/// On write error, close/reopen the device and retry up to 10 times.
/// Prints "device: progress%" to stdout.
fn write_image(image: &Path, device: &Path, dev_label: &str) -> Result<(), String> {
    let image_size = fs::metadata(image)
        .map_err(|e| format!("failed to stat image: {}", e))?
        .len();

    let mut src = File::open(image)
        .map_err(|e| format!("failed to open image: {}", e))?;

    let mut dst = open_output_device(device)
        .map_err(|e| format!("failed to open device: {}", e))?;

    // O_DIRECT requires page-aligned buffers. Allocate with proper alignment.
    let align = 4096usize;
    let layout = std::alloc::Layout::from_size_align(CHUNK_SIZE, align)
        .map_err(|e| format!("layout error: {}", e))?;
    let buf_ptr = unsafe { std::alloc::alloc(layout) };
    if buf_ptr.is_null() {
        return Err("failed to allocate aligned buffer".to_string());
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, CHUNK_SIZE) };

    let mut written: u64 = 0;
    let mut retries: u32 = 0;
    let mut last_pct: u64 = u64::MAX; // force first print

    let result = loop {
        let n = match src.read(buf) {
            Ok(0) => break Ok(()),
            Ok(n) => n,
            Err(e) => break Err(format!("failed to read image: {}", e)),
        };

        // O_DIRECT requires writes to be sector-aligned in size.
        // Pad the final chunk up to a 512-byte boundary.
        let write_len = if n % 512 != 0 {
            let padded = (n + 511) & !511;
            // zero out the padding bytes
            for b in &mut buf[n..padded] {
                *b = 0;
            }
            padded
        } else {
            n
        };

        if let Err(e) = dst.write_all(&buf[..write_len]) {
            error!("{}: write error at offset {}: {}", dev_label, written, e);
            retries += 1;
            if retries > MAX_RETRIES {
                break Err(format!(
                    "aborting after {} retries, last error: {}",
                    MAX_RETRIES, e
                ));
            }
            // Close, wait, reopen, seek, and retry this chunk.
            drop(dst);
            warn!(
                "{}: retry {}/{} — waiting {}s...",
                dev_label,
                retries,
                MAX_RETRIES,
                RETRY_DELAY.as_secs()
            );
            thread::sleep(RETRY_DELAY);
            dst = match open_output_device(device) {
                Ok(f) => f,
                Err(e2) => {
                    break Err(format!("failed to reopen device on retry: {}", e2));
                }
            };
            if let Err(e2) = dst.seek(SeekFrom::Start(written)) {
                break Err(format!("failed to seek on retry: {}", e2));
            }
            // Also rewind the source to re-read this chunk.
            if let Err(e2) = src.seek(SeekFrom::Start(written)) {
                break Err(format!("failed to seek source on retry: {}", e2));
            }
            continue;
        }

        written += n as u64;

        // Print progress
        let pct = if image_size > 0 {
            (written * 100) / image_size
        } else {
            100
        };
        if pct != last_pct {
            println!("{}: {}%", dev_label, pct);
            last_pct = pct;
        }
    };

    unsafe { std::alloc::dealloc(buf_ptr, layout) };
    result
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
