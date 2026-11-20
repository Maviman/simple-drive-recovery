# simple-drive-recovery: DriveDoctor

Diagnostic and repair tool for SD cards and USB thumb drives on Windows 10/11.
`drivedoctor.exe` is a single standalone Rust executable (no crates, no runtime). A PowerShell version with the same features is in `powershell/`.

## Build and run

    cargo build --release
    target\release\drivedoctor.exe          # interactive menu, asks for admin rights
    target\release\drivedoctor.exe --list   # print removable drives and exit (read-only)

Builds with the MSVC or GNU Windows toolchain. Press **Esc** to stop a running test.

PowerShell version: double-click `powershell\DriveDoctor.cmd`. It also writes logs to `powershell\logs\`.

## Safety rails

- Only disks with bus type **USB, SD or MMC** are listed or accepted.
- Refuses boot/system disks, the disk holding the Windows drive, any page file, or the disk the script runs from.
- Destructive actions need you to type `ERASE <disk number>`, and abort if the disk's name, serial or size changed since you picked it.
- Warns when a "removable" disk reports more than 512 GB (external SSD/HDD, or a fake card).
- Caveat: a USB-attached external HDD/SSD also has bus type USB. Check the name and size on the confirm screen.

## Menu

| # | Action | Data |
|---|--------|------|
| 1 | List removable drives (size, partition style, status, read-only, offline, letters) | kept |
| 2 | Details and health: disk/partition/volume info, 4 MiB alignment, unallocated space, SMART counters (rarely exposed by flash), registry write-protect policy, `disk` driver errors in the System log for the last 7 days (bad block, I/O retried, surprise removal) | kept |
| 3 | Clear read-only: registry `StorageDevicePolicies\WriteProtect`, `Set-Disk`, diskpart disk + volume attributes, bring online, then a real write test | kept |
| 4 | `chkdsk /f /x` on each volume | kept |
| 5 | Raw read of every sector via `\\.\PhysicalDriveN` (unbuffered, 4 MiB chunks; failing chunks are re-read per sector to count bad sectors) | kept |
| 6 | Quick fake-capacity probe: 64 KiB blocks on a power-of-two grid (>= 256 points) across the reported size, written then read back | **erased** |
| 7 | Full write + verify of every sector (H2testw / f3 equivalent). Reports speed, bad sectors, and real capacity. Can then create a partition limited to the verified-good region | **erased** |
| 8 | diskpart `clean`, MBR, one primary partition aligned to 4 MiB, quick format FAT32 (<= 32 GB) / exFAT / NTFS, assign letter | **erased** |

### How the fake-capacity detection works

Each 512-byte sector is written with word 0 = `offset XOR seed` and the rest from a
SplitMix64 stream keyed on the absolute byte offset and a random per-run seed. On readback,
a wrong sector whose header and body are a valid pattern for a *different* offset means the
controller aliases high addresses onto low ones (classic fake card); the distance gives the
wraparound period. Total verified-good bytes give the real capacity for both wraparound
fakes and fakes that drop/error writes past their real size. Scattered failures are reported
as worn/defective flash instead.

## What software can and cannot fix

Fixable: corrupt/RAW file systems, damaged or odd partition tables, leftover hidden/OEM
partitions, Windows read-only/offline flags, the registry write-protect policy, misaligned
partitions, fake cards (by limiting the partition to the real capacity).

Not fixable here: a physical lock switch (check microSD adapters too), a controller that
has put itself into permanent read-only mode (normal end-of-life behaviour for flash), a
card that disappears or reports 0 bytes / "No media" (dead controller; only vendor
mass-production tools can sometimes reflash it).

## Established alternatives

- **SD Memory Card Formatter** (SD Association): formats to the spec layout for SD/SDHC/SDXC. Best "make this card normal again" tool for SD.
- **H2testw** (heise): the standard Windows write/verify test for capacity and integrity, works through the file system.
- **f3** (`f3probe`, `f3write`/`f3read`, Linux/macOS): fast destructive fake-capacity probe; `f3fix` creates a correctly sized partition.
- **ValiDrive** (GRC): quick, free fake-capacity check for USB drives.
- **Rufus**: can run a multi-pass bad-block check while formatting.
- **ChipGenius / Flash Drive Information Extractor**: identifies the USB controller so you can find the vendor's mass-production tool for a stick that no longer formats.

## Rust vs PowerShell version

Same menu, safety rails and fake-capacity algorithm. The Rust build enumerates disks with IOCTLs
(`IOCTL_STORAGE_QUERY_PROPERTY`, `IOCTL_DISK_GET_DRIVE_LAYOUT_EX`, ...) instead of `Get-Disk`, also refuses
any disk with a volume containing `\Windows\System32\ntoskrnl.exe`, skips SMART counters (flash media
essentially never exposes them), and adds `--list`. Both still call diskpart, chkdsk and wevtutil.
