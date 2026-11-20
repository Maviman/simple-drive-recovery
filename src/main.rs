//! DriveDoctor - diagnostic and repair tool for SD cards and USB thumb drives (Windows).
//!
//! Single executable, no external crates. Only disks on the USB, SD or MMC bus are accepted;
//! the disk holding Windows, a page file, or this program is always refused, and every
//! destructive action needs "ERASE <disk number>" typed in.
//!
//!   1  List removable drives
//!   2  Details and health report
//!   3  Clear read-only / bring online
//!   4  Repair file system (chkdsk /f)                      keeps data
//!   5  Read surface scan                                   keeps data
//!   6  Quick fake-capacity probe                           ERASES
//!   7  Full write + verify of every sector (H2testw / f3)  ERASES
//!   8  Wipe, repartition (MBR, 4 MiB aligned), format      ERASES
//!
//! Command line: `drivedoctor --list` prints the drive list and exits.

#![cfg_attr(not(windows), allow(dead_code, unused_imports))]
#![allow(non_snake_case, clippy::upper_case_acronyms)]

use std::collections::hash_map::RandomState;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufRead, Write};
use std::process::Command;
use std::ptr::{null, null_mut};
use std::time::Instant;

// ===================================================================== Win32 FFI
type HANDLE = *mut c_void;
type BOOL = i32;
const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 4;
const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 4;
const KEY_EVENT: u16 = 1;
const VK_ESCAPE: u16 = 0x1B;

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00A0;
const IOCTL_DISK_GET_DRIVE_LAYOUT_EX: u32 = 0x0007_0050;
const IOCTL_DISK_IS_WRITABLE: u32 = 0x0007_0024;
const IOCTL_DISK_GET_DISK_ATTRIBUTES: u32 = 0x0007_00F0;

const ERROR_WRITE_PROTECT: u32 = 19;
const TOKEN_QUERY: u32 = 8;
const TOKEN_ELEVATION_CLASS: u32 = 20;
const RRF_RT_REG_DWORD: u32 = 0x18;
const REG_DWORD: u32 = 4;
const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;

const BUS_USB: u32 = 7;
const BUS_SD: u32 = 0xC;
const BUS_MMC: u32 = 0xD;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct InputRecord {
    event_type: u16,
    _pad: u16,
    key_down: i32,
    repeat: u16,
    vk: u16,
    scan: u16,
    ch: u16,
    ctrl: u32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(name: *const u16, access: u32, share: u32, sa: *mut c_void, disp: u32, flags: u32, tmpl: HANDLE) -> HANDLE;
    fn CloseHandle(h: HANDLE) -> BOOL;
    fn ReadFile(h: HANDLE, buf: *mut c_void, n: u32, done: *mut u32, ov: *mut c_void) -> BOOL;
    fn WriteFile(h: HANDLE, buf: *const c_void, n: u32, done: *mut u32, ov: *mut c_void) -> BOOL;
    fn SetFilePointerEx(h: HANDLE, dist: i64, newpos: *mut i64, method: u32) -> BOOL;
    fn FlushFileBuffers(h: HANDLE) -> BOOL;
    fn DeviceIoControl(h: HANDLE, code: u32, inb: *const c_void, insz: u32, outb: *mut c_void, outsz: u32, ret: *mut u32, ov: *mut c_void) -> BOOL;
    fn GetLastError() -> u32;
    fn VirtualAlloc(addr: *mut c_void, size: usize, ty: u32, prot: u32) -> *mut c_void;
    fn VirtualFree(addr: *mut c_void, size: usize, ty: u32) -> BOOL;
    fn GetStdHandle(n: u32) -> HANDLE;
    fn GetConsoleMode(h: HANDLE, mode: *mut u32) -> BOOL;
    fn SetConsoleMode(h: HANDLE, mode: u32) -> BOOL;
    fn GetNumberOfConsoleInputEvents(h: HANDLE, n: *mut u32) -> BOOL;
    fn ReadConsoleInputW(h: HANDLE, buf: *mut InputRecord, len: u32, read: *mut u32) -> BOOL;
    fn GetVolumeInformationW(root: *const u16, name: *mut u16, namesz: u32, serial: *mut u32, maxcomp: *mut u32, flags: *mut u32, fs: *mut u16, fssz: u32) -> BOOL;
    fn GetDiskFreeSpaceExW(root: *const u16, avail: *mut u64, total: *mut u64, free: *mut u64) -> BOOL;
    fn GetFileAttributesW(name: *const u16) -> u32;
    fn GetCurrentProcess() -> HANDLE;
    fn GetLogicalDrives() -> u32;
    fn GetWindowsDirectoryW(buf: *mut u16, size: u32) -> u32;
}

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(p: HANDLE, access: u32, tok: *mut HANDLE) -> BOOL;
    fn GetTokenInformation(tok: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> BOOL;
    fn RegGetValueW(hkey: isize, sub: *const u16, val: *const u16, flags: u32, ty: *mut u32, data: *mut c_void, len: *mut u32) -> i32;
    fn RegSetKeyValueW(hkey: isize, sub: *const u16, val: *const u16, ty: u32, data: *const c_void, len: u32) -> i32;
}

#[cfg(windows)]
#[link(name = "shell32")]
extern "system" {
    fn ShellExecuteW(hwnd: *mut c_void, op: *const u16, file: *const u16, params: *const u16, dir: *const u16, show: i32) -> isize;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

// ===================================================================== console output
static mut COLOR: bool = false;

fn enable_colors() {
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) != 0 && SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 {
            COLOR = true;
        }
    }
}

fn paint(code: &str, s: &str) -> String {
    if unsafe { COLOR } { format!("\x1b[{}m{}\x1b[0m", code, s) } else { s.to_string() }
}
fn info(s: &str) { println!("  {}", s); }
fn good(s: &str) { println!("  {}", paint("92", s)); }
fn warn(s: &str) { println!("  {}", paint("93", s)); }
fn bad(s: &str) { println!("  {}", paint("91", s)); }
fn head(s: &str) { println!("  {}", paint("96", s)); }
fn dim(s: &str) { println!("    {}", paint("90", s)); }

/// Returns None on end of input.
fn prompt(msg: &str) -> Option<String> {
    print!("  {}: ", msg);
    let _ = io::stdout().flush();
    let mut s = String::new();
    match io::stdin().lock().read_line(&mut s) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(s.trim().to_string()),
    }
}

fn yes_default(msg: &str) -> bool {
    !matches!(prompt(msg).as_deref().map(|s| s.to_ascii_lowercase()), Some(ref s) if s.starts_with('n'))
}
fn no_default(msg: &str) -> bool {
    matches!(prompt(msg).as_deref().map(|s| s.to_ascii_lowercase()), Some(ref s) if s.starts_with('y'))
}

/// True if Esc was pressed since the last call. Drains pending console input events.
fn user_abort() -> bool {
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut n = 0u32;
        while GetNumberOfConsoleInputEvents(h, &mut n) != 0 && n > 0 {
            let mut rec = InputRecord::default();
            let mut read = 0u32;
            if ReadConsoleInputW(h, &mut rec, 1, &mut read) == 0 || read == 0 {
                return false;
            }
            if rec.event_type == KEY_EVENT && rec.key_down != 0 && rec.vk == VK_ESCAPE {
                return true;
            }
        }
    }
    false
}

fn fmt_bytes(b: u64) -> String {
    let f = b as f64;
    if f >= 1e12 { format!("{:.2} TB", f / 1e12) }
    else if f >= 1e9 { format!("{:.2} GB", f / 1e9) }
    else if f >= 1e6 { format!("{:.1} MB", f / 1e6) }
    else { format!("{} bytes", b) }
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out
}

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const LARGE_DISK_WARN: u64 = 512 * GIB;

// ===================================================================== handles and buffers
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0); }
    }
}

fn open_path(path: &str, access: u32, flags: u32) -> Result<Handle, u32> {
    let w = wide(path);
    let h = unsafe { CreateFileW(w.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, null_mut(), OPEN_EXISTING, flags, null_mut()) };
    if h == INVALID_HANDLE_VALUE { Err(unsafe { GetLastError() }) } else { Ok(Handle(h)) }
}

fn open_disk(n: u32, write: bool) -> Result<Handle, u32> {
    let access = GENERIC_READ | if write { GENERIC_WRITE } else { 0 };
    open_path(&format!(r"\\.\PhysicalDrive{}", n), access, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH)
}

fn ioctl(h: &Handle, code: u32, input: &[u8], out: &mut [u8]) -> Result<u32, u32> {
    let mut ret = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            h.0, code,
            if input.is_empty() { null() } else { input.as_ptr() as *const c_void }, input.len() as u32,
            if out.is_empty() { null_mut() } else { out.as_mut_ptr() as *mut c_void }, out.len() as u32,
            &mut ret, null_mut(),
        )
    };
    if ok != 0 { Ok(ret) } else { Err(unsafe { GetLastError() }) }
}

fn rd_u32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn rd_u64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

/// Page-aligned buffer (required for FILE_FLAG_NO_BUFFERING).
struct AlignedBuf { ptr: *mut u8, len: usize }
impl AlignedBuf {
    fn new(len: usize) -> AlignedBuf {
        let p = unsafe { VirtualAlloc(null_mut(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) } as *mut u8;
        assert!(!p.is_null(), "VirtualAlloc failed");
        AlignedBuf { ptr: p, len }
    }
    fn words(&mut self, bytes: usize) -> &mut [u64] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u64, bytes.min(self.len) / 8) }
    }
}
impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe { VirtualFree(self.ptr as *mut c_void, 0, MEM_RELEASE); }
    }
}

fn read_at(h: &Handle, off: u64, buf: &AlignedBuf, len: usize) -> Result<(), u32> {
    unsafe {
        if SetFilePointerEx(h.0, off as i64, null_mut(), 0) == 0 { return Err(GetLastError()); }
        let mut n = 0u32;
        if ReadFile(h.0, buf.ptr as *mut c_void, len as u32, &mut n, null_mut()) == 0 { return Err(GetLastError()); }
        if n as usize != len { return Err(23); }
    }
    Ok(())
}

fn write_at(h: &Handle, off: u64, buf: &AlignedBuf, len: usize) -> Result<(), u32> {
    unsafe {
        if SetFilePointerEx(h.0, off as i64, null_mut(), 0) == 0 { return Err(GetLastError()); }
        let mut n = 0u32;
        if WriteFile(h.0, buf.ptr as *const c_void, len as u32, &mut n, null_mut()) == 0 { return Err(GetLastError()); }
        if n as usize != len { return Err(29); }
    }
    Ok(())
}

// ===================================================================== disk enumeration
#[derive(Clone)]
struct Part {
    number: u32,
    offset: u64,
    length: u64,
}

#[derive(Clone)]
struct DiskInfo {
    num: u32,
    vendor: String,
    product: String,
    revision: String,
    serial: String,
    bus: u32,
    removable_media: bool,
    media_type: u32,
    size: u64,
    sector: u32,
    style: Option<u32>, // 0 MBR, 1 GPT, 2 RAW
    parts: Vec<Part>,
    read_only: bool,
    offline: bool,
    letters: Vec<(char, u32)>, // drive letter, partition number
}

impl DiskInfo {
    fn name(&self) -> String {
        let s = format!("{} {}", self.vendor, self.product);
        let s = s.trim();
        if s.is_empty() { "(unnamed)".into() } else { s.to_string() }
    }
    fn letters_str(&self) -> String {
        self.letters.iter().map(|(l, _)| format!("{}:", l)).collect::<Vec<_>>().join(" ")
    }
    fn style_str(&self) -> &'static str {
        match self.style { Some(0) => "MBR", Some(1) => "GPT", Some(2) => "RAW", _ => "?" }
    }
    fn sector_size(&self) -> u64 {
        let s = self.sector as u64;
        if s < 512 || s % 512 != 0 { 512 } else { s }
    }
}

fn bus_name(b: u32) -> &'static str {
    match b {
        1 => "SCSI", 2 => "ATAPI", 3 => "ATA", 4 => "1394", 5 => "SSA", 6 => "Fibre", 7 => "USB", 8 => "RAID",
        9 => "iSCSI", 0xA => "SAS", 0xB => "SATA", 0xC => "SD", 0xD => "MMC", 0xE => "Virtual",
        0xF => "FileBacked", 0x10 => "Spaces", 0x11 => "NVMe", 0x12 => "SCM", 0x13 => "UFS", _ => "Unknown",
    }
}

fn allowed_bus(b: u32) -> bool { b == BUS_USB || b == BUS_SD || b == BUS_MMC }

fn cstr_at(buf: &[u8], off: u32) -> String {
    let o = off as usize;
    if o == 0 || o >= buf.len() { return String::new(); }
    let end = buf[o..].iter().position(|&c| c == 0).map(|p| o + p).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[o..end]).trim().to_string()
}

/// Map of drive letter -> (disk number, partition number) for every lettered volume.
fn letter_map() -> Vec<(char, u32, u32)> {
    let mut v = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 { continue; }
        let l = (b'A' + i as u8) as char;
        if let Ok(h) = open_path(&format!(r"\\.\{}:", l), 0, 0) {
            let mut out = [0u8; 12];
            if ioctl(&h, IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], &mut out).is_ok() {
                let dev_type = rd_u32(&out, 0);
                if dev_type == 7 { // FILE_DEVICE_DISK
                    v.push((l, rd_u32(&out, 4), rd_u32(&out, 8)));
                }
            }
        }
    }
    v
}

fn query_disk(n: u32, letters: &[(char, u32, u32)]) -> Option<DiskInfo> {
    let h = open_path(&format!(r"\\.\PhysicalDrive{}", n), GENERIC_READ, 0)
        .or_else(|_| open_path(&format!(r"\\.\PhysicalDrive{}", n), 0, 0))
        .ok()?;

    // StorageDeviceProperty, PropertyStandardQuery
    let q = [0u8; 12];
    let mut desc = vec![0u8; 1024];
    let mut d = DiskInfo {
        num: n, vendor: String::new(), product: String::new(), revision: String::new(), serial: String::new(),
        bus: 0, removable_media: false, media_type: 0, size: 0, sector: 512, style: None, parts: Vec::new(),
        read_only: false, offline: false, letters: Vec::new(),
    };
    if ioctl(&h, IOCTL_STORAGE_QUERY_PROPERTY, &q, &mut desc).is_ok() {
        d.removable_media = desc[10] != 0;
        d.vendor = cstr_at(&desc, rd_u32(&desc, 12));
        d.product = cstr_at(&desc, rd_u32(&desc, 16));
        d.revision = cstr_at(&desc, rd_u32(&desc, 20));
        d.serial = cstr_at(&desc, rd_u32(&desc, 24));
        d.bus = rd_u32(&desc, 28);
    }

    let mut len = [0u8; 8];
    if ioctl(&h, IOCTL_DISK_GET_LENGTH_INFO, &[], &mut len).is_ok() {
        d.size = rd_u64(&len, 0);
    }
    let mut geo = [0u8; 256];
    if ioctl(&h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], &mut geo).is_ok() {
        d.media_type = rd_u32(&geo, 8);
        d.sector = rd_u32(&geo, 20);
        if d.size == 0 { d.size = rd_u64(&geo, 24); }
    }
    let mut layout = vec![0u8; 48 + 144 * 128];
    if ioctl(&h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], &mut layout).is_ok() {
        let style = rd_u32(&layout, 0);
        let count = rd_u32(&layout, 4) as usize;
        d.style = Some(style);
        for i in 0..count.min(128) {
            let e = 48 + i * 144;
            let offset = rd_u64(&layout, e + 8);
            let length = rd_u64(&layout, e + 16);
            let number = rd_u32(&layout, e + 24);
            let mbr_type = layout[e + 32];
            if length == 0 || (style == 0 && mbr_type == 0) { continue; }
            d.parts.push(Part { number, offset, length });
        }
    }
    let mut attrs = [0u8; 16];
    if ioctl(&h, IOCTL_DISK_GET_DISK_ATTRIBUTES, &[], &mut attrs).is_ok() {
        let a = rd_u64(&attrs, 8);
        d.offline = a & 1 != 0;
        d.read_only = a & 2 != 0;
    }
    if d.size > 0 {
        if let Err(e) = ioctl(&h, IOCTL_DISK_IS_WRITABLE, &[], &mut []) {
            if e == ERROR_WRITE_PROTECT { d.read_only = true; }
        }
    }
    d.letters = letters.iter().filter(|(_, dn, _)| *dn == n).map(|(l, _, p)| (*l, *p)).collect();
    Some(d)
}

fn all_disks() -> Vec<DiskInfo> {
    let lm = letter_map();
    (0..64).filter_map(|n| query_disk(n, &lm)).collect()
}

fn candidate_disks() -> Vec<DiskInfo> {
    all_disks().into_iter().filter(|d| allowed_bus(d.bus)).collect()
}

fn get_disk(n: u32) -> Option<DiskInfo> {
    query_disk(n, &letter_map())
}

fn system_letter() -> char {
    let mut buf = [0u16; 260];
    let n = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), 260) };
    if n > 0 { from_wide(&buf).chars().next().unwrap_or('C').to_ascii_uppercase() } else { 'C' }
}

fn file_exists(p: &str) -> bool {
    let w = wide(p);
    unsafe { GetFileAttributesW(w.as_ptr()) != INVALID_FILE_ATTRIBUTES }
}

/// Re-reads the disk and refuses anything that is not plainly a removable USB/SD/MMC disk.
fn assert_safe(n: u32) -> Result<DiskInfo, String> {
    let d = get_disk(n).ok_or(format!("Disk {} not found.", n))?;
    if !allowed_bus(d.bus) {
        return Err(format!("Disk {} has bus type {}, not USB/SD/MMC. Refusing.", n, bus_name(d.bus)));
    }
    let sys = system_letter();
    if d.letters.iter().any(|(l, _)| *l == sys) {
        return Err(format!("Disk {} holds the Windows drive ({}:). Refusing.", n, sys));
    }
    if let Ok(exe) = std::env::current_exe() {
        let s = exe.to_string_lossy().to_string();
        let s = s.trim_start_matches(r"\\?\");
        let mut it = s.chars();
        if let (Some(l), Some(':')) = (it.next(), it.next()) {
            let l = l.to_ascii_uppercase();
            if d.letters.iter().any(|(x, _)| *x == l) {
                return Err(format!("DriveDoctor is running from disk {} ({}:). Copy it to another drive first.", n, l));
            }
        }
    }
    for (l, _) in &d.letters {
        if file_exists(&format!(r"{}:\pagefile.sys", l)) || file_exists(&format!(r"{}:\swapfile.sys", l)) {
            return Err(format!("Disk {} holds a page file ({}:). Refusing.", n, l));
        }
        if file_exists(&format!(r"{}:\Windows\System32\ntoskrnl.exe", l)) {
            return Err(format!("Disk {} has a Windows installation on {}:. Refusing.", n, l));
        }
    }
    Ok(d)
}

fn same_disk(a: &DiskInfo) -> bool {
    match get_disk(a.num) {
        Some(b) => b.product == a.product && b.vendor == a.vendor && b.serial == a.serial && b.size == a.size,
        None => false,
    }
}

// ===================================================================== UI: disk selection
fn show_disks() -> Vec<DiskInfo> {
    let disks = candidate_disks();
    if disks.is_empty() {
        warn("No USB/SD/MMC disks found. Insert the card/drive, wait a few seconds, try again.");
        warn("(Some PCIe card readers report as SCSI/NVMe; DriveDoctor deliberately ignores those. Use a USB reader.)");
        return disks;
    }
    println!();
    println!("  {:>4}  {:<30} {:<4} {:>10}  {:<5} {:<9} {:<8} {}", "Disk", "Name", "Bus", "Size", "Style", "ReadOnly", "Offline", "Letters");
    println!("  {:>4}  {:<30} {:<4} {:>10}  {:<5} {:<9} {:<8} {}", "----", "----", "---", "----", "-----", "--------", "-------", "-------");
    for d in &disks {
        let size = if d.size > 0 { fmt_bytes(d.size) } else { "no media".into() };
        let mut name = d.name();
        if name.len() > 30 { name.truncate(30); }
        println!("  {:>4}  {:<30} {:<4} {:>10}  {:<5} {:<9} {:<8} {}",
            d.num, name, bus_name(d.bus), size, d.style_str(), d.read_only, d.offline, d.letters_str());
    }
    println!();
    disks
}

fn select_disk() -> Option<DiskInfo> {
    let disks = show_disks();
    if disks.is_empty() { return None; }
    let ans = prompt("Disk number (blank = cancel)")?;
    if ans.is_empty() { return None; }
    let n: u32 = match ans.parse() { Ok(n) => n, Err(_) => { warn("Not a number."); return None; } };
    if !disks.iter().any(|d| d.num == n) { bad(&format!("Disk {} is not in the removable list. Refusing.", n)); return None; }
    match assert_safe(n) {
        Ok(d) if d.size == 0 => { warn(&format!("Disk {} has no media.", n)); None }
        Ok(d) => Some(d),
        Err(e) => { bad(&e); None }
    }
}

fn confirm_destructive(d: &DiskInfo, action: &str) -> bool {
    println!();
    bad(&format!("!!! {} ERASES EVERYTHING on this disk !!!", action));
    bad(&format!("Disk {}: {}  [{}]  {}  serial {}", d.num, d.name(), bus_name(d.bus), fmt_bytes(d.size), d.serial));
    if !d.letters.is_empty() { bad(&format!("Mounted as: {}", d.letters_str())); }
    if d.size > LARGE_DISK_WARN {
        warn("This disk reports more than 512 GB. That is unusual for an SD card or thumb drive: it may be an");
        warn("external SSD/HDD, or a fake-capacity card (those often claim 1-2 TB). Double-check before continuing.");
    }
    let expect = format!("ERASE {}", d.num);
    let ans = prompt(&format!("Type '{}' to continue", expect)).unwrap_or_default();
    if !ans.eq_ignore_ascii_case(&expect) { warn("Cancelled."); return false; }
    if !same_disk(d) { bad("The disk changed since it was selected (removed or swapped). Cancelled."); return false; }
    true
}

// ===================================================================== diskpart / external tools
fn diskpart(lines: &[String]) -> i32 {
    let path = std::env::temp_dir().join(format!("dd_diskpart_{}.txt", std::process::id()));
    if let Err(e) = std::fs::write(&path, lines.join("\r\n") + "\r\n") {
        bad(&format!("Cannot write diskpart script: {}", e));
        return -1;
    }
    let out = Command::new("diskpart.exe").arg("/s").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) => {
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                if !l.trim().is_empty() { dim(l.trim_end()); }
            }
            o.status.code().unwrap_or(-1)
        }
        Err(e) => { bad(&format!("Cannot run diskpart: {}", e)); -1 }
    }
}

fn dp_clean(n: u32) -> i32 {
    diskpart(&[format!("select disk {}", n), "clean".into()])
}

fn clean_for_raw_access(d: &DiskInfo) -> bool {
    if let Err(e) = assert_safe(d.num) { bad(&e); return false; }
    info("Removing partitions (diskpart clean)...");
    let code = diskpart(&[
        format!("select disk {}", d.num),
        "attributes disk clear readonly noerr".into(),
        "online disk noerr".into(),
        "clean".into(),
    ]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let d2 = get_disk(d.num);
    if code != 0 || d2.as_ref().map(|x| x.read_only).unwrap_or(true) {
        bad(&format!("Could not clean the disk (diskpart exit code {}).", code));
        warn("If it reports write protection: check the SD lock switch (also on microSD adapters) and try option 3.");
        warn("If it stays write-protected, the controller has locked the flash read-only (typical end of life). Replace it.");
        return false;
    }
    true
}

fn reg_write_protect() -> Option<u32> {
    let sub = wide(r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies");
    let val = wide("WriteProtect");
    let mut data = 0u32;
    let mut len = 4u32;
    let r = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, sub.as_ptr(), val.as_ptr(), RRF_RT_REG_DWORD, null_mut(), &mut data as *mut u32 as *mut c_void, &mut len) };
    if r == 0 { Some(data) } else { None }
}

fn reg_clear_write_protect() -> bool {
    let sub = wide(r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies");
    let val = wide("WriteProtect");
    let zero = 0u32;
    unsafe { RegSetKeyValueW(HKEY_LOCAL_MACHINE, sub.as_ptr(), val.as_ptr(), REG_DWORD, &zero as *const u32 as *const c_void, 4) == 0 }
}

struct VolInfo { fs: String, label: String, free: u64 }

fn volume_info(l: char) -> Option<VolInfo> {
    let root = wide(&format!(r"{}:\", l));
    let mut name = [0u16; 261];
    let mut fs = [0u16; 261];
    let (mut serial, mut maxc, mut flags) = (0u32, 0u32, 0u32);
    let ok = unsafe { GetVolumeInformationW(root.as_ptr(), name.as_mut_ptr(), 261, &mut serial, &mut maxc, &mut flags, fs.as_mut_ptr(), 261) };
    if ok == 0 { return None; }
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut avail, &mut total, &mut free); }
    Some(VolInfo { fs: from_wide(&fs), label: from_wide(&name), free })
}

// ===================================================================== raw test engine
const CHUNK: usize = 4 * 1024 * 1024;
const MAX_CONSEC_CHUNK_FAILS: u32 = 16;
const MAX_BAD_SECTORS: u64 = 500_000;

#[derive(Default)]
struct TestResult {
    size: u64,
    bytes_written: u64,
    bytes_verified: u64,
    sectors_tested: u64,
    good_sectors: u64,
    bad_sectors: u64,      // I/O errors
    mismatch_sectors: u64, // read OK, data wrong
    alias_sectors: u64,    // wrong data that belongs to another offset (address wraparound)
    alias_period: u64,     // smallest wraparound distance seen
    first_bad: Option<u64>,
    write_mibps: f64,
    read_mibps: f64,
    aborted: bool,
    device_lost: bool,
    abort_reason: String,
    probe_offsets: Vec<u64>,
    probe_status: Vec<u8>, // 0 ok, 1 write err, 2 read err, 3 wrong data, 4 alias
}

impl TestResult {
    fn mark_bad(&mut self, off: u64) {
        if self.first_bad.map_or(true, |f| off < f) { self.first_bad = Some(off); }
    }
    fn abort(&mut self, why: String) {
        self.aborted = true;
        if self.abort_reason.is_empty() { self.abort_reason = why; }
    }
}

fn is_fatal(err: u32) -> bool {
    // not ready, device gone, no such device, device not connected, invalid handle
    matches!(err, 21 | 55 | 433 | 1167 | 6)
}

#[inline]
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Pattern word at absolute byte position `pos`. The first word of every sector is
/// (offset XOR seed) so a misplaced sector reveals which offset it was written for.
#[inline]
fn pattern(pos: u64, sector_start: bool, seed: u64) -> u64 {
    if sector_start { pos ^ seed } else { mix(pos ^ seed) }
}

fn fill(w: &mut [u64], off: u64, seed: u64, wps: usize) {
    for (i, x) in w.iter_mut().enumerate() {
        *x = pattern(off + 8 * i as u64, i % wps == 0, seed);
    }
}

/// Compares a buffer read from `off` against the pattern. Returns (bad sectors, any alias).
fn compare(r: &mut TestResult, got: &[u64], off: u64, seed: u64, wps: usize, sector: u64, size: u64) -> (u64, bool) {
    let mut badn = 0;
    let mut any_alias = false;
    let mut b = 0;
    while b < got.len() {
        r.sectors_tested += 1;
        let so = off + 8 * b as u64;
        let ok = (0..wps).all(|k| got[b + k] == pattern(so + 8 * k as u64, k == 0, seed));
        if ok {
            r.good_sectors += 1;
        } else {
            badn += 1;
            r.mismatch_sectors += 1;
            r.mark_bad(so);
            let src = got[b] ^ seed;
            if src != so && src < size && src % sector == 0
                && (1..wps).all(|k| got[b + k] == mix((src + 8 * k as u64) ^ seed))
            {
                any_alias = true;
                r.alias_sectors += 1;
                let p = src.abs_diff(so);
                if r.alias_period == 0 || p < r.alias_period { r.alias_period = p; }
            }
        }
        b += wps;
    }
    (badn, any_alias)
}

struct Progress { start: Instant, last: f64, phase: &'static str }
impl Progress {
    fn new(phase: &'static str) -> Progress { Progress { start: Instant::now(), last: -10.0, phase } }
    fn secs(&self) -> f64 { self.start.elapsed().as_secs_f64().max(0.001) }
    fn show(&mut self, done: u64, total: u64, errors: u64, force: bool) {
        let t = self.start.elapsed().as_secs_f64();
        if !force && t - self.last < 1.0 { return; }
        self.last = t;
        let rate = done as f64 / MIB as f64 / self.secs();
        let pct = if total > 0 { 100.0 * done as f64 / total as f64 } else { 100.0 };
        let eta = if rate > 0.01 {
            let s = ((total - done) as f64 / MIB as f64 / rate) as u64;
            format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
        } else { "--:--:--".into() };
        print!("\r  {:<9} {:>6.2}%  {:>7.1} MiB/s  ETA {}  bad sectors {}     ", self.phase, pct, rate, eta, errors);
        let _ = io::stdout().flush();
    }
    fn done(&mut self, done: u64, total: u64, errors: u64) {
        self.show(done, total, errors, true);
        println!();
    }
}

fn read_scan(n: u32, size: u64, sector: u64) -> Result<TestResult, String> {
    let mut r = TestResult { size, ..Default::default() };
    let h = open_disk(n, false).map_err(|e| format!("Cannot open PhysicalDrive{} (Win32 error {})", n, e))?;
    let buf = AlignedBuf::new(CHUNK);
    let mut p = Progress::new("Reading");
    let mut consec = 0;
    let mut off = 0u64;
    while off < size {
        if user_abort() { r.abort("Stopped by user (Esc).".into()); break; }
        let len = (CHUNK as u64).min(size - off) as usize;
        let secs = len as u64 / sector;
        match read_at(&h, off, &buf, len) {
            Ok(()) => { consec = 0; r.good_sectors += secs; }
            Err(e) if is_fatal(e) => {
                r.device_lost = true;
                r.abort(format!("Device stopped responding (Win32 error {}) at byte {}.", e, off));
                break;
            }
            Err(_) => {
                consec += 1;
                if consec >= MAX_CONSEC_CHUNK_FAILS {
                    r.bad_sectors += secs; r.mark_bad(off);
                    r.abort(format!("Reads keep failing from about byte {}; stopping.", off));
                    break;
                }
                // isolate bad sectors; give up on the chunk after 64 failures in a row
                let mut consec_sec = 0;
                let mut s = off;
                while s < off + len as u64 {
                    if consec_sec >= 64 || read_at(&h, s, &buf, sector as usize).is_err() {
                        r.bad_sectors += 1; r.mark_bad(s); consec_sec += 1;
                    } else { consec_sec = 0; r.good_sectors += 1; }
                    s += sector;
                }
                if r.bad_sectors > MAX_BAD_SECTORS { r.abort("Too many bad sectors; stopping.".into()); break; }
            }
        }
        r.sectors_tested += secs;
        off += len as u64;
        r.bytes_verified = off;
        p.show(off, size, r.bad_sectors, false);
    }
    p.done(r.bytes_verified, size, r.bad_sectors);
    r.read_mibps = r.bytes_verified as f64 / MIB as f64 / p.secs();
    Ok(r)
}

fn write_verify(n: u32, size: u64, sector: u64, seed: u64) -> Result<TestResult, String> {
    let mut r = TestResult { size, ..Default::default() };
    let wps = (sector / 8) as usize;
    let h = open_disk(n, true).map_err(|e| format!("Cannot open PhysicalDrive{} for writing (Win32 error {})", n, e))?;
    let mut buf = AlignedBuf::new(CHUNK);

    // ---- write pass
    let mut p = Progress::new("Writing");
    let mut consec = 0;
    let mut off = 0u64;
    let mut user_stopped = false;
    while off < size {
        if user_abort() { r.abort("Stopped by user (Esc) during write pass.".into()); user_stopped = true; break; }
        let len = (CHUNK as u64).min(size - off) as usize;
        fill(buf.words(len), off, seed, wps);
        match write_at(&h, off, &buf, len) {
            Ok(()) => consec = 0,
            Err(e) if is_fatal(e) => {
                r.device_lost = true;
                r.abort(format!("Device stopped responding (Win32 error {}) while writing at byte {}.", e, off));
                break;
            }
            Err(_) => {
                r.bad_sectors += len as u64 / sector; r.mark_bad(off);
                consec += 1;
                if consec >= MAX_CONSEC_CHUNK_FAILS {
                    off += len as u64; r.bytes_written = off;
                    r.abort(format!("Writes keep failing from about byte {}; the device likely has less real capacity than it reports.",
                        off.saturating_sub(consec as u64 * CHUNK as u64)));
                    break;
                }
            }
        }
        off += len as u64;
        r.bytes_written = off;
        p.show(off, size, r.bad_sectors, false);
    }
    unsafe { FlushFileBuffers(h.0); }
    p.done(r.bytes_written, size, r.bad_sectors);
    r.write_mibps = r.bytes_written as f64 / MIB as f64 / p.secs();

    // ---- verify pass
    if !r.device_lost && !user_stopped {
        let limit = r.bytes_written;
        let mut p = Progress::new("Verifying");
        consec = 0;
        off = 0;
        while off < limit {
            if user_abort() { r.abort("Stopped by user (Esc) during verify pass.".into()); break; }
            let len = (CHUNK as u64).min(limit - off) as usize;
            match read_at(&h, off, &buf, len) {
                Ok(()) => {
                    consec = 0;
                    let got = buf.words(len);
                    compare(&mut r, got, off, seed, wps, sector, size);
                }
                Err(e) if is_fatal(e) => {
                    r.device_lost = true;
                    r.abort(format!("Device stopped responding (Win32 error {}) while verifying at byte {}.", e, off));
                    break;
                }
                Err(_) => {
                    r.bad_sectors += len as u64 / sector; r.sectors_tested += len as u64 / sector; r.mark_bad(off);
                    consec += 1;
                    if consec >= MAX_CONSEC_CHUNK_FAILS { r.abort("Reads keep failing during verify; stopping.".into()); break; }
                }
            }
            off += len as u64;
            r.bytes_verified = off;
            p.show(off, limit, r.bad_sectors + r.mismatch_sectors, false);
        }
        p.done(r.bytes_verified, limit, r.bad_sectors + r.mismatch_sectors);
        r.read_mibps = r.bytes_verified as f64 / MIB as f64 / p.secs();
    }
    Ok(r)
}

/// Writes 64 KiB blocks on a power-of-two grid (>= 256 points) across the reported size,
/// then reads them back. Catches devices that error out, return junk, or wrap high addresses
/// onto low ones when the wrap lands on another probe. Not a substitute for the full test.
fn quick_probe(n: u32, size: u64, sector: u64, seed: u64) -> Result<TestResult, String> {
    const BLOCK: u64 = 64 * 1024;
    let mut r = TestResult { size, ..Default::default() };
    let wps = (sector / 8) as usize;
    let mut step: u64 = GIB;
    while step > BLOCK && size / step < 256 { step >>= 1; }
    let mut offs = Vec::new();
    let mut o = 0u64;
    while o + BLOCK <= size { offs.push(o); o += step; }
    let last = (size - BLOCK) / sector * sector;
    if offs.last() != Some(&last) { offs.push(last); }
    r.probe_status = vec![0; offs.len()];
    r.probe_offsets = offs.clone();
    let total = offs.len() as u64 * BLOCK;

    let h = open_disk(n, true).map_err(|e| format!("Cannot open PhysicalDrive{} for writing (Win32 error {})", n, e))?;
    let mut buf = AlignedBuf::new(BLOCK as usize);

    let mut p = Progress::new("Writing");
    for (i, &o) in offs.iter().enumerate() {
        if user_abort() { r.abort("Stopped by user (Esc).".into()); return Ok(r); }
        fill(buf.words(BLOCK as usize), o, seed, wps);
        if let Err(e) = write_at(&h, o, &buf, BLOCK as usize) {
            if is_fatal(e) {
                r.device_lost = true;
                r.abort(format!("Device stopped responding (Win32 error {}) while writing probe at byte {}.", e, o));
                return Ok(r);
            }
            r.probe_status[i] = 1; r.bad_sectors += BLOCK / sector; r.mark_bad(o);
        }
        r.bytes_written += BLOCK;
        p.show((i as u64 + 1) * BLOCK, total, r.bad_sectors, false);
    }
    unsafe { FlushFileBuffers(h.0); }
    p.done(total, total, r.bad_sectors);

    let mut p = Progress::new("Verifying");
    for (i, &o) in offs.iter().enumerate() {
        if user_abort() { r.abort("Stopped by user (Esc).".into()); return Ok(r); }
        match read_at(&h, o, &buf, BLOCK as usize) {
            Err(e) if is_fatal(e) => {
                r.device_lost = true;
                r.abort(format!("Device stopped responding (Win32 error {}) while reading probe at byte {}.", e, o));
                return Ok(r);
            }
            Err(_) => {
                if r.probe_status[i] == 0 { r.probe_status[i] = 2; }
                r.bad_sectors += BLOCK / sector; r.mark_bad(o);
            }
            Ok(()) => {
                let got = buf.words(BLOCK as usize);
                let (badn, alias) = compare(&mut r, got, o, seed, wps, sector, size);
                if badn > 0 && r.probe_status[i] == 0 { r.probe_status[i] = if alias { 4 } else { 3 }; }
            }
        }
        r.bytes_verified += BLOCK;
        p.show((i as u64 + 1) * BLOCK, total, r.bad_sectors + r.mismatch_sectors, false);
    }
    p.done(total, total, r.bad_sectors + r.mismatch_sectors);
    Ok(r)
}

#[derive(PartialEq)]
enum Verdict { Pass, FakeWrap(u64), FakeTail(u64), Scattered, Incomplete }

fn seq_verdict(r: &TestResult, sector: u64) -> Verdict {
    if r.bad_sectors + r.mismatch_sectors == 0 && !r.aborted { return Verdict::Pass; }
    if r.alias_sectors > 0 { return Verdict::FakeWrap(r.good_sectors * sector); }
    if let Some(fb) = r.first_bad {
        let total = r.size / sector;
        let failed = total.saturating_sub(r.good_sectors);
        let tail = (r.size - fb) / sector;
        if tail > 0 && failed as f64 >= 0.9 * tail as f64 { return Verdict::FakeTail(fb); }
        return Verdict::Scattered;
    }
    Verdict::Incomplete
}

fn show_result(r: &TestResult, name: &str) {
    println!();
    head(&format!("---- {} result ----", name));
    info(&format!("Reported size        : {}  ({} bytes)", fmt_bytes(r.size), group(r.size)));
    if r.bytes_written > 0 { info(&format!("Written              : {}", fmt_bytes(r.bytes_written))); }
    info(&format!("Read back            : {}", fmt_bytes(r.bytes_verified)));
    if r.write_mibps > 0.0 { info(&format!("Write speed          : {:.1} MiB/s", r.write_mibps)); }
    if r.read_mibps > 0.0 { info(&format!("Read speed           : {:.1} MiB/s", r.read_mibps)); }
    info(&format!("I/O error sectors    : {}", group(r.bad_sectors)));
    if r.mismatch_sectors > 0 || r.bytes_written > 0 {
        info(&format!("Wrong-data sectors   : {}  (of which {} hold data written for another address)", group(r.mismatch_sectors), group(r.alias_sectors)));
    }
    if let Some(fb) = r.first_bad { info(&format!("First failure at     : byte {}  ({})", group(fb), fmt_bytes(fb))); }
    if r.aborted { warn(&format!("Stopped early: {}", r.abort_reason)); }
}

fn new_seed() -> u64 {
    // std seeds RandomState from the OS RNG
    let mut h = RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    h.finish()
}

// ===================================================================== menu actions
fn choose_fs(bytes: u64) -> &'static str {
    let default = if bytes <= 32 * GIB { "FAT32" } else { "exFAT" };
    info("1) FAT32  - widest compatibility, 4 GB max file size; Windows only formats it up to 32 GB");
    info("2) exFAT  - standard for SDXC (>32 GB), cameras, phones, consoles");
    info("3) NTFS   - Windows only");
    let mut fs = match prompt(&format!("File system [default {}]", default)).as_deref() {
        Some("1") => "FAT32", Some("2") => "exFAT", Some("3") => "NTFS", _ => default,
    };
    if fs == "FAT32" && bytes > 32 * GIB {
        warn("Windows refuses FAT32 above 32 GB; using exFAT instead. (Need FAT32 on a big card? Use a third-party formatter.)");
        fs = "exFAT";
    }
    fs
}

fn reformat(disk: Option<DiskInfo>, max_bytes: u64) {
    let d = match disk {
        Some(d) => d,
        None => {
            let Some(d) = select_disk() else { return };
            if !confirm_destructive(&d, "Wipe + repartition + format") { return; }
            d
        }
    };
    let d = match assert_safe(d.num) { Ok(x) => x, Err(e) => { bad(&e); return; } };
    let part_bytes = if max_bytes > 0 { max_bytes.min(d.size) } else { d.size };
    let fs = choose_fs(part_bytes);
    let raw = prompt("Volume label (max 11 chars, blank = USBDRIVE)").unwrap_or_default();
    let mut label: String = raw.chars().filter(|c| c.is_ascii_alphanumeric() || " _-".contains(*c)).collect();
    label = label.trim().chars().take(11).collect::<String>().trim().to_string();
    if label.is_empty() { label = "USBDRIVE".into(); }

    let mut create = "create partition primary align=4096".to_string();
    if max_bytes > 0 {
        let mb = max_bytes / MIB;
        create = format!("create partition primary size={} align=4096", mb);
        warn(&format!("Partition limited to {} MiB (verified-good region).", group(mb)));
    }
    info(&format!("Partitioning and formatting as {}...", fs));
    let code = diskpart(&[
        format!("select disk {}", d.num),
        "attributes disk clear readonly noerr".into(),
        "online disk noerr".into(),
        "clean".into(),
        "convert mbr".into(),
        create,
        format!("format fs={} label=\"{}\" quick", fs.to_lowercase(), label),
        "assign".into(),
    ]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    if code != 0 {
        bad(&format!("diskpart failed (exit code {}). See the output above.", code));
        warn("Write protected -> lock switch / option 3. \"I/O device error\" or timeouts -> failing flash or controller.");
        return;
    }
    good("Format complete.");
    if let Some(d2) = get_disk(d.num) {
        for (l, _) in &d2.letters {
            if let Some(v) = volume_info(*l) {
                info(&format!("{}:  {}  label '{}'  free {}", l, v.fs, v.label, fmt_bytes(v.free)));
            }
        }
    }
}

fn recent_disk_events(n: u32) -> Option<Vec<(u32, usize)>> {
    let q = "*[System[Provider[@Name='disk'] and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
    let out = Command::new("wevtutil.exe")
        .args(["qe", "System", &format!("/q:{}", q), "/f:text", "/rd:true", "/c:1000"])
        .output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let needle = format!("\\Harddisk{}\\", n);
    let mut counts: Vec<(u32, usize)> = Vec::new();
    for block in text.split("Event[").skip(1) {
        if !block.contains(&needle) { continue; }
        let id = block.lines()
            .find_map(|l| l.trim().strip_prefix("Event ID:").map(|v| v.trim().parse::<u32>().unwrap_or(0)))
            .unwrap_or(0);
        match counts.iter_mut().find(|(i, _)| *i == id) {
            Some(c) => c.1 += 1,
            None => counts.push((id, 1)),
        }
    }
    Some(counts)
}

fn details() {
    let Some(d) = select_disk() else { return };
    println!();
    info(&format!("Disk number          : {}", d.num));
    info(&format!("Vendor / product     : {} / {}", d.vendor, d.product));
    info(&format!("Firmware revision    : {}", d.revision));
    info(&format!("Serial number        : {}", d.serial));
    info(&format!("Bus                  : {}", bus_name(d.bus)));
    info(&format!("Media                : {}", match d.media_type { 11 => "removable", 12 => "fixed", _ => "unknown" }));
    info(&format!("Size                 : {}  ({} bytes)", fmt_bytes(d.size), group(d.size)));
    info(&format!("Sector size          : {}", d.sector));
    info(&format!("Partition style      : {}", d.style_str()));
    info(&format!("Read-only            : {}", d.read_only));
    info(&format!("Offline              : {}", d.offline));

    if d.parts.is_empty() {
        warn("No partitions: the disk is blank/RAW or its partition table is unreadable. Option 8 rebuilds it.");
    } else {
        println!();
        println!("  {:>4} {:>6} {:>14} {:>9} {:>10} {:<10} {:<12} {:>10}", "Part", "Letter", "Offset", "4MiB-algn", "Size", "FS", "Label", "Free");
        let mut misaligned = false;
        let mut raw = false;
        for p in &d.parts {
            let letter = d.letters.iter().find(|(_, pn)| *pn == p.number).map(|(l, _)| *l);
            let v = letter.and_then(volume_info);
            let aligned = p.offset % (4 * MIB) == 0;
            misaligned |= !aligned;
            let fs = match (&letter, &v) {
                (Some(_), Some(v)) if !v.fs.is_empty() => v.fs.clone(),
                (Some(_), _) => { raw = true; "RAW".into() }
                (None, _) => "(no letter)".into(),
            };
            println!("  {:>4} {:>6} {:>14} {:>9} {:>10} {:<10} {:<12} {:>10}",
                p.number, letter.map(|l| format!("{}:", l)).unwrap_or_default(), group(p.offset), aligned,
                fmt_bytes(p.length), fs, v.as_ref().map(|v| v.label.clone()).unwrap_or_default(),
                v.as_ref().map(|v| fmt_bytes(v.free)).unwrap_or_default());
        }
        println!();
        if misaligned { warn("A partition is not 4 MiB aligned. Flash erase blocks are typically 4 MiB; reformatting (option 8) fixes this and can improve write speed."); }
        if raw { warn("RAW volume: the file system is unreadable. Option 4 may fix minor damage; otherwise option 8."); }
        let used: u64 = d.parts.iter().map(|p| p.length).sum();
        if d.size > 0 && (used as f64) < 0.9 * d.size as f64 {
            warn(&format!("Partitions cover only {} of {}. Option 8 reclaims the rest.", fmt_bytes(used), fmt_bytes(d.size)));
        }
    }
    info("SMART/reliability counters: not read (SD cards and nearly all USB sticks do not expose them).");

    if reg_write_protect() == Some(1) {
        bad("Registry policy StorageDevicePolicies\\WriteProtect = 1: Windows blocks writes to ALL USB storage. Option 3 can clear it.");
    }

    match recent_disk_events(d.num) {
        Some(c) if !c.is_empty() => {
            let total: usize = c.iter().map(|x| x.1).sum();
            warn(&format!("{} disk driver events in the last 7 days mention Harddisk{} (disk numbers can be reused by other devices):", total, d.num));
            for (id, cnt) in c {
                let desc = match id { 7 => "bad block", 11 => "controller error", 51 => "error during paging", 153 => "I/O retried",
                    154 => "I/O failed (hardware)", 157 => "surprise removal", _ => "" };
                info(&format!("  event {:<4} x{:<5} {}", id, cnt, desc));
            }
        }
        Some(_) => good(&format!("No disk driver errors logged for Harddisk{} in the last 7 days.", d.num)),
        None => info("Could not read the System event log."),
    }

    println!();
    if d.read_only { bad("Disk is READ-ONLY. Try option 3. If it will not clear: lock switch, or the controller has locked itself (end of life)."); }
    if d.offline { warn("Disk is OFFLINE. Option 3 brings it online."); }
    if d.style == Some(2) { warn("Disk is uninitialized (RAW). Option 8 partitions and formats it."); }
    if d.size > LARGE_DISK_WARN { warn("Reported size is very large for removable flash; run option 6 or 7 to rule out a fake-capacity device."); }
}

fn clear_read_only() {
    let Some(d) = select_disk() else { return };
    if reg_write_protect() == Some(1)
        && no_default("Registry policy WriteProtect=1 blocks writes to ALL USB storage. Set it to 0? (y/N)")
    {
        if reg_clear_write_protect() { good("Policy cleared. Unplug and reinsert the drive afterwards."); }
        else { bad("Could not change the registry value."); }
    }
    let mut lines = vec![
        format!("select disk {}", d.num),
        "attributes disk clear readonly noerr".into(),
        "online disk noerr".into(),
    ];
    for (l, _) in &d.letters {
        lines.push(format!("select volume {}", l));
        lines.push("attributes volume clear readonly noerr".into());
        lines.push("attributes volume clear hidden noerr".into());
    }
    diskpart(&lines);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let Some(d2) = get_disk(d.num) else { bad("Disk disappeared."); return };
    if d2.read_only {
        bad("Still read-only. Causes, most likely first:");
        info(" - SD / microSD-adapter lock switch is in the LOCK position (slide it toward the contacts).");
        info(" - The card controller has permanently switched to read-only. Flash controllers do this at end of life");
        info("   or after detecting too many failed blocks. Software cannot undo it; copy anything you need and replace it.");
        return;
    }
    good("Disk read-only flag is clear.");
    for (l, _) in &d2.letters {
        let path = format!(r"{}:\dd_write_test_{:016x}.tmp", l, new_seed());
        let res = (|| -> io::Result<()> {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&path)?;
            f.write_all(b"DriveDoctor write test")?;
            f.sync_all()?;
            drop(f);
            std::fs::remove_file(&path)
        })();
        match res {
            Ok(()) => good(&format!("Write test on {}: OK.", l)),
            Err(e) => bad(&format!("Write test on {}: failed - {}", l, e)),
        }
    }
}

fn repair_fs() {
    let Some(d) = select_disk() else { return };
    if d.letters.is_empty() { warn("No mounted volumes. If the disk shows as RAW, its file system is gone: use option 8."); return; }
    for (l, _) in &d.letters {
        info(&format!("chkdsk {}: /f /x", l));
        let code = Command::new("chkdsk.exe").arg(format!("{}:", l)).args(["/f", "/x"]).status()
            .ok().and_then(|s| s.code()).unwrap_or(-1);
        match code {
            0 => good(&format!("{}: no errors found.", l)),
            1 => good(&format!("{}: errors found and fixed.", l)),
            2 => good(&format!("{}: cleanup performed, no errors.", l)),
            _ => bad(&format!("{}: chkdsk could not check or fix the volume (exit {}). Reformat with option 8.", l, code)),
        }
    }
}

fn surface_scan() {
    let Some(d) = select_disk() else { return };
    let ss = d.sector_size();
    info(&format!("Reading all {} - nothing is written. Press Esc to stop.", fmt_bytes(d.size)));
    let r = match read_scan(d.num, d.size, ss) { Ok(r) => r, Err(e) => { bad(&e); return; } };
    show_result(&r, "Read surface scan");
    if r.bad_sectors == 0 && !r.aborted {
        good("PASS: every sector is readable.");
    } else if r.bad_sectors > 0 {
        bad(&format!("FAIL: {} unreadable sectors. Flash with read errors keeps degrading; a full write test (7)", group(r.bad_sectors)));
        bad("can show whether the controller remaps them, but plan to replace this card.");
    }
    if r.read_mibps > 0.0 && r.read_mibps < 5.0 && !r.aborted {
        warn("Very low read speed: worn flash, a USB 1.1 port/hub, or a poor reader.");
    }
}

fn probe() {
    let Some(d) = select_disk() else { return };
    if !confirm_destructive(&d, "Quick fake-capacity probe") { return; }
    if !clean_for_raw_access(&d) { return; }
    let ss = d.sector_size();
    let r = match quick_probe(d.num, d.size, ss, new_seed()) { Ok(r) => r, Err(e) => { bad(&e); return; } };
    show_result(&r, "Quick probe");
    let n = r.probe_status.len();
    let bad_idx: Vec<usize> = (0..n).filter(|&i| r.probe_status[i] != 0).collect();
    if r.device_lost {
        bad("The device dropped off the bus during the probe. Typical of fakes and dying controllers.");
        return;
    }
    if !bad_idx.is_empty() {
        let first = bad_idx[0];
        let names = ["", "write error", "read error", "wrong data", "data from another address"];
        let mut parts = Vec::new();
        for s in 1..=4u8 {
            let c = r.probe_status.iter().filter(|&&x| x == s).count();
            if c > 0 { parts.push(format!("{} {}", c, names[s as usize])); }
        }
        bad(&format!("FAIL: {} of {} probe points bad ({}).", bad_idx.len(), n, parts.join(", ")));
        if r.alias_sectors > 0 {
            bad(&format!("Address wraparound detected (period {0}). This is a FAKE-CAPACITY device; real capacity is about {0} or less.", fmt_bytes(r.alias_period)));
        } else if bad_idx.len() == n - first {
            let good_to = if first > 0 { r.probe_offsets[first - 1] } else { 0 };
            bad(&format!("Everything from {} upward fails; the last good probe is at {}. Real capacity is about {} - likely a FAKE-CAPACITY device.",
                fmt_bytes(r.probe_offsets[first]), fmt_bytes(good_to), fmt_bytes(good_to)));
        } else {
            bad("Failures are scattered rather than a clean upper region: defective/worn flash rather than a fake.");
        }
        warn("Run option 7 next: it measures the exact usable capacity and can create a safe, smaller partition.");
        dp_clean(d.num);
        return;
    }
    if r.aborted { dp_clean(d.num); return; }
    good(&format!("PASS: all {} probe points across the full {} read back correctly.", n, fmt_bytes(r.size)));
    info("Not a crude fake. Option 7 tests every sector if you want certainty.");
    if yes_default("The disk is now blank. Partition and format it now? (Y/n)") {
        reformat(get_disk(d.num), 0);
    } else {
        dp_clean(d.num);
        info("Left blank (uninitialized).");
    }
}

fn full_test() {
    let Some(d) = select_disk() else { return };
    warn(&format!("This writes and then reads all {}. At 20 MB/s that is roughly {:.0} minutes per pass, two passes.",
        fmt_bytes(d.size), d.size as f64 / 20e6 / 60.0));
    if !confirm_destructive(&d, "Full write + verify test") { return; }
    if !clean_for_raw_access(&d) { return; }
    let ss = d.sector_size();
    let r = match write_verify(d.num, d.size, ss, new_seed()) { Ok(r) => r, Err(e) => { bad(&e); return; } };
    show_result(&r, "Full write + verify");
    let v = seq_verdict(&r, ss);
    let mut limit = 0u64;
    match v {
        Verdict::Pass => good("PASS: every sector held the data written to it. The full capacity is genuine and usable."),
        Verdict::FakeWrap(usable) => {
            bad(&format!("FAKE CAPACITY: high addresses wrap onto low ones (period {}).", fmt_bytes(r.alias_period)));
            bad(&format!("Real, usable capacity is about {} of the {} reported.", fmt_bytes(usable), fmt_bytes(r.size)));
            limit = (usable as f64 * 0.98) as u64;
        }
        Verdict::FakeTail(usable) => {
            bad(&format!("Everything from {0} upward fails. Usable capacity is about {0} of the {1} reported.", fmt_bytes(usable), fmt_bytes(r.size)));
            bad("If that is far below the label, the device is a FAKE-CAPACITY device.");
            limit = (usable as f64 * 0.98) as u64;
        }
        Verdict::Scattered => bad(&format!("FAIL: {} bad sectors scattered across the device. The flash is defective or worn out; replace it.",
            group(r.bad_sectors + r.mismatch_sectors))),
        Verdict::Incomplete => warn("Test did not complete; no verdict."),
    }
    if r.device_lost { bad("The device dropped off the bus during the test. Reinsert it before doing anything else."); return; }

    if limit > 8 * MIB {
        if yes_default(&format!("Create a partition limited to the verified-good {}? (Y/n)", fmt_bytes(limit))) {
            reformat(get_disk(d.num), limit);
            return;
        }
    } else if v == Verdict::Pass {
        if yes_default("The disk holds test data only. Partition and format it now? (Y/n)") {
            reformat(get_disk(d.num), 0);
            return;
        }
    } else if v == Verdict::Scattered
        && no_default("Format it anyway (not recommended - expect silent data corruption)? (y/N)")
    {
        reformat(get_disk(d.num), 0);
        return;
    }
    dp_clean(d.num);
    info("Disk left blank (uninitialized).");
}

// ===================================================================== elevation and main
fn is_elevated() -> bool {
    unsafe {
        let mut tok: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 { return false; }
        let tok = Handle(tok);
        let mut elev = 0u32;
        let mut ret = 0u32;
        GetTokenInformation(tok.0, TOKEN_ELEVATION_CLASS, &mut elev as *mut u32 as *mut c_void, 4, &mut ret) != 0 && elev != 0
    }
}

fn relaunch_elevated() -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let file = wide(&exe.to_string_lossy());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let params = wide(&args.join(" "));
    let op = wide("runas");
    let r = unsafe { ShellExecuteW(null_mut(), op.as_ptr(), file.as_ptr(), params.as_ptr(), null(), 1) };
    r > 32
}

fn pause_exit(code: i32) -> ! {
    let _ = prompt("Press Enter to close");
    std::process::exit(code)
}

fn main() {
    enable_colors();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h" || a == "/?") {
        println!("DriveDoctor {} - removable drive diagnostics and repair", env!("CARGO_PKG_VERSION"));
        println!("  drivedoctor          interactive menu (asks for administrator rights)");
        println!("  drivedoctor --list   print removable drives and exit");
        return;
    }
    if args.iter().any(|a| a == "--list") {
        if !is_elevated() { warn("Not running as administrator: sizes and layouts may be missing."); }
        show_disks();
        return;
    }
    if !is_elevated() {
        warn("DriveDoctor needs administrator rights for raw disk access. Relaunching elevated...");
        if relaunch_elevated() { return; }
        bad("Elevation was refused or failed. Right-click drivedoctor.exe and choose 'Run as administrator'.");
        pause_exit(1);
    }

    println!();
    head(&format!("DriveDoctor {} - removable drive diagnostics and repair", env!("CARGO_PKG_VERSION")));
    println!("  {}", paint("36", "Only USB / SD / MMC disks are listed; the Windows disk is always refused. Esc stops a running test."));

    loop {
        println!();
        info("1  List removable drives");
        info("2  Details and health report");
        info("3  Clear read-only / bring online");
        info("4  Repair file system (chkdsk /f)           keeps data");
        info("5  Read surface scan                         keeps data");
        warn("6  Quick fake-capacity probe (~1 min)        ERASES");
        warn("7  Full write + verify test (slow)           ERASES");
        warn("8  Wipe, repartition and format              ERASES");
        info("Q  Quit");
        let Some(c) = prompt("Choice") else { break };
        // drain any keypresses typed before a test starts so a stray Esc does not abort it
        while user_abort() {}
        match c.to_ascii_uppercase().as_str() {
            "1" => { show_disks(); }
            "2" => details(),
            "3" => clear_read_only(),
            "4" => repair_fs(),
            "5" => surface_scan(),
            "6" => probe(),
            "7" => full_test(),
            "8" => reformat(None, 0),
            "Q" => break,
            _ => {}
        }
    }
}
