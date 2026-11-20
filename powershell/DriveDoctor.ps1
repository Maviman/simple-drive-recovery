<#
.SYNOPSIS
    DriveDoctor - diagnostic and repair tool for SD cards and USB thumb drives (Windows).

.DESCRIPTION
    Interactive menu. Only works on disks whose bus type is USB, SD or MMC, and refuses
    boot/system disks, the disk holding the Windows drive, a page file, or this script.
    Every destructive action requires typing "ERASE <disk number>".

    1  List removable drives
    2  Details and health report (status, partitions, alignment, read-only flags, recent disk errors)
    3  Clear read-only / bring disk online (disk + volume attributes, registry policy)
    4  Repair file system (chkdsk /f)                       - keeps data
    5  Read surface scan of every sector                     - keeps data
    6  Quick fake-capacity probe                             - ERASES the disk
    7  Full write + verify of every sector (H2testw / f3)    - ERASES the disk
    8  Wipe, repartition (MBR, 4 MiB aligned) and format     - ERASES the disk

    Logs are written to .\logs next to this script.
    Run from a normal PowerShell console (not the ISE). Press Esc to stop a running test.
#>
[CmdletBinding()]
param(
    # Also accept fixed-media disks over 256 GiB (external HDD/SSD). Dangerous.
    [switch]$AllowLargeFixed
)

$ErrorActionPreference = 'Continue'
$Version = '1.0'
$AllowedBusTypes = @('USB', 'SD', 'MMC')
$LargeDiskWarnBytes = 512GB
$FixedMediaLimitBytes = 256GB

# ---------------------------------------------------------------- elevation
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'DriveDoctor needs administrator rights for raw disk access. Relaunching elevated...' -ForegroundColor Yellow
    $exe = (Get-Process -Id $PID).Path
    $relArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"")
    if ($AllowLargeFixed) { $relArgs += '-AllowLargeFixed' }
    Start-Process -FilePath $exe -Verb RunAs -ArgumentList $relArgs
    return
}

# ---------------------------------------------------------------- logging
$LogDir = Join-Path $PSScriptRoot 'logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir ('DriveDoctor_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))
try { Start-Transcript -Path $LogFile | Out-Null } catch { }

# ---------------------------------------------------------------- raw I/O engine (C#)
$engine = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DriveDoctor
{
    public class TestResult
    {
        public long Size;
        public long BytesWritten;
        public long BytesVerified;
        public long SectorsTested;
        public long GoodSectors;
        public long BadSectors;       // I/O errors (read or write failed)
        public long MismatchSectors;  // read OK but data wrong
        public long AliasSectors;     // wrong data that belongs to a different offset (address wraparound = fake capacity)
        public long AliasPeriod;      // smallest wraparound distance seen, bytes
        public long FirstBadOffset = -1;
        public double WriteMBps;
        public double ReadMBps;
        public bool Aborted;
        public bool DeviceLost;
        public string AbortReason = "";
        public long[] ProbeOffsets;
        public int[] ProbeStatus;     // 0 ok, 1 write error, 2 read error, 3 wrong data, 4 wrong data from another offset (alias)
    }

    public static class RawDisk
    {
        const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
        const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, OPEN_EXISTING = 3;
        const uint FILE_FLAG_NO_BUFFERING = 0x20000000, FILE_FLAG_WRITE_THROUGH = 0x80000000;
        const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000, PAGE_READWRITE = 4;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(SafeFileHandle h, IntPtr buf, uint n, out uint done, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteFile(SafeFileHandle h, IntPtr buf, uint n, out uint done, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFilePointerEx(SafeFileHandle h, long dist, out long newPos, uint method);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FlushFileBuffers(SafeFileHandle h);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint type);

        const int Chunk = 4 * 1024 * 1024;
        const int MaxConsecutiveChunkFailures = 16;
        const long MaxBadSectors = 500000;
        static long _last;

        static bool IsFatal(int err)
        {
            // not ready, device gone, no such device, device not connected, invalid handle
            return err == 21 || err == 55 || err == 433 || err == 1167 || err == 6;
        }

        static SafeFileHandle Open(int disk, bool write)
        {
            SafeFileHandle h = CreateFile(@"\\.\PhysicalDrive" + disk,
                GENERIC_READ | (write ? GENERIC_WRITE : 0u),
                FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, IntPtr.Zero);
            if (h.IsInvalid)
                throw new Exception("Cannot open PhysicalDrive" + disk + " (Win32 error " + Marshal.GetLastWin32Error() + ")");
            return h;
        }

        static IntPtr Alloc(int n)
        {
            IntPtr p = VirtualAlloc(IntPtr.Zero, new UIntPtr((uint)n), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (p == IntPtr.Zero) throw new OutOfMemoryException("VirtualAlloc failed");
            return p;
        }

        static void Free(IntPtr p) { if (p != IntPtr.Zero) VirtualFree(p, UIntPtr.Zero, MEM_RELEASE); }

        static bool ReadAt(SafeFileHandle h, long off, IntPtr buf, int len, out int err)
        {
            long np; uint n; err = 0;
            if (!SetFilePointerEx(h, off, out np, 0)) { err = Marshal.GetLastWin32Error(); return false; }
            if (!ReadFile(h, buf, (uint)len, out n, IntPtr.Zero)) { err = Marshal.GetLastWin32Error(); return false; }
            if (n != (uint)len) { err = 23; return false; }
            return true;
        }

        static bool WriteAt(SafeFileHandle h, long off, IntPtr buf, int len, out int err)
        {
            long np; uint n; err = 0;
            if (!SetFilePointerEx(h, off, out np, 0)) { err = Marshal.GetLastWin32Error(); return false; }
            if (!WriteFile(h, buf, (uint)len, out n, IntPtr.Zero)) { err = Marshal.GetLastWin32Error(); return false; }
            if (n != (uint)len) { err = 29; return false; }
            return true;
        }

        static ulong Mix(ulong z)
        {
            z += 0x9E3779B97F4A7C15UL;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
            return z ^ (z >> 31);
        }

        // Each sector: word 0 = (absolute byte offset XOR seed), remaining words = Mix(position XOR seed).
        // Word 0 lets a mismatching sector tell us which offset its data was really written for.
        static void Fill(long[] a, int words, long off, ulong seed, int wps)
        {
            for (int i = 0; i < words; i++)
            {
                ulong pos = (ulong)(off + 8L * i);
                a[i] = (i % wps == 0) ? (long)(pos ^ seed) : (long)Mix(pos ^ seed);
            }
        }

        static bool IsAlias(long[] got, int b, int wps, ulong seed, long size, int sector, out long src)
        {
            src = (long)((ulong)got[b] ^ seed);
            if (src < 0 || src >= size || (src % sector) != 0) return false;
            for (int k = 1; k < wps; k++)
                if (got[b + k] != (long)Mix((ulong)(src + 8L * k) ^ seed)) return false;
            return true;
        }

        // Returns number of bad sectors in this buffer; updates result counters.
        static int Compare(TestResult r, long[] pat, long[] got, int words, long off, ulong seed, int wps, int sector, long size, out bool anyAlias)
        {
            int bad = 0; anyAlias = false;
            for (int b = 0; b < words; b += wps)
            {
                r.SectorsTested++;
                bool ok = true;
                for (int k = 0; k < wps; k++) if (pat[b + k] != got[b + k]) { ok = false; break; }
                if (ok) { r.GoodSectors++; continue; }
                bad++;
                long so = off + 8L * b;
                r.MismatchSectors++;
                MarkBad(r, so);
                long src;
                if (IsAlias(got, b, wps, seed, size, sector, out src) && src != so)
                {
                    anyAlias = true;
                    r.AliasSectors++;
                    long period = Math.Abs(src - so);
                    if (r.AliasPeriod == 0 || period < r.AliasPeriod) r.AliasPeriod = period;
                }
            }
            return bad;
        }

        static void MarkBad(TestResult r, long off) { if (r.FirstBadOffset < 0 || off < r.FirstBadOffset) r.FirstBadOffset = off; }

        static void Abort(TestResult r, string why) { r.Aborted = true; if (r.AbortReason.Length == 0) r.AbortReason = why; }

        static bool UserAbort()
        {
            try { while (Console.KeyAvailable) if (Console.ReadKey(true).Key == ConsoleKey.Escape) return true; }
            catch { }
            return false;
        }

        static void Progress(string phase, long done, long total, Stopwatch sw, TestResult r, bool force)
        {
            long now = sw.ElapsedMilliseconds;
            if (!force && now - _last < 1000) return;
            _last = now;
            double secs = Math.Max(sw.Elapsed.TotalSeconds, 0.001);
            double rate = done / 1048576.0 / secs;
            double pct = total > 0 ? 100.0 * done / total : 100.0;
            string eta = rate > 0.01 ? TimeSpan.FromSeconds((long)((total - done) / 1048576.0 / rate)).ToString() : "--:--:--";
            Console.Write("\r  {0,-9} {1,6:F2}%  {2,7:F1} MiB/s  ETA {3}  bad sectors {4}     ",
                phase, pct, rate, eta, r.BadSectors + r.MismatchSectors);
        }

        // ------------------------------------------------------------ read-only scan
        public static TestResult ReadScan(int disk, long size, int sector)
        {
            TestResult r = new TestResult(); r.Size = size;
            IntPtr buf = Alloc(Chunk);
            try
            {
                using (SafeFileHandle h = Open(disk, false))
                {
                    Stopwatch sw = Stopwatch.StartNew(); _last = -10000;
                    int consec = 0; long off = 0;
                    while (off < size)
                    {
                        if (UserAbort()) { Abort(r, "Stopped by user (Esc)."); break; }
                        int len = (int)Math.Min((long)Chunk, size - off);
                        long secs = len / sector;
                        int err;
                        if (ReadAt(h, off, buf, len, out err)) { consec = 0; r.GoodSectors += secs; }
                        else
                        {
                            if (IsFatal(err)) { r.DeviceLost = true; Abort(r, "Device stopped responding (Win32 error " + err + ") at byte " + off + "."); break; }
                            if (++consec >= MaxConsecutiveChunkFailures)
                            {
                                r.BadSectors += secs; MarkBad(r, off);
                                Abort(r, "Reads keep failing from about byte " + off + "; stopping.");
                                break;
                            }
                            // isolate the bad sectors inside this chunk (give up on the chunk after 64 failures in a row)
                            int consecSec = 0;
                            for (long s = off; s < off + len; s += sector)
                            {
                                int e2 = 0;
                                if (consecSec >= 64 || !ReadAt(h, s, buf, sector, out e2)) { r.BadSectors++; MarkBad(r, s); consecSec++; }
                                else { consecSec = 0; r.GoodSectors++; }
                            }
                            if (r.BadSectors > MaxBadSectors) { Abort(r, "Too many bad sectors; stopping."); break; }
                        }
                        r.SectorsTested += secs;
                        off += len;
                        r.BytesVerified = off;
                        Progress("Reading", off, size, sw, r, false);
                    }
                    Progress("Reading", r.BytesVerified, size, sw, r, true);
                    Console.WriteLine();
                    r.ReadMBps = r.BytesVerified / 1048576.0 / Math.Max(sw.Elapsed.TotalSeconds, 0.001);
                }
            }
            finally { Free(buf); }
            return r;
        }

        // ------------------------------------------------------------ full write + verify (destructive)
        public static TestResult WriteVerify(int disk, long size, int sector, ulong seed)
        {
            TestResult r = new TestResult(); r.Size = size;
            int wps = sector / 8;
            IntPtr buf = Alloc(Chunk);
            long[] pat = new long[Chunk / 8];
            long[] got = new long[Chunk / 8];
            try
            {
                using (SafeFileHandle h = Open(disk, true))
                {
                    // write pass
                    Stopwatch sw = Stopwatch.StartNew(); _last = -10000;
                    int consec = 0; long off = 0; int err; bool userStopped = false;
                    while (off < size)
                    {
                        if (UserAbort()) { Abort(r, "Stopped by user (Esc) during write pass."); userStopped = true; break; }
                        int len = (int)Math.Min((long)Chunk, size - off);
                        int words = len / 8;
                        Fill(pat, words, off, seed, wps);
                        Marshal.Copy(pat, 0, buf, words);
                        if (WriteAt(h, off, buf, len, out err)) consec = 0;
                        else
                        {
                            if (IsFatal(err)) { r.DeviceLost = true; Abort(r, "Device stopped responding (Win32 error " + err + ") while writing at byte " + off + "."); break; }
                            r.BadSectors += len / sector; MarkBad(r, off);
                            if (++consec >= MaxConsecutiveChunkFailures)
                            {
                                off += len; r.BytesWritten = off;
                                Abort(r, "Writes keep failing from about byte " + (off - (long)consec * Chunk) + "; the device likely has less real capacity than it reports.");
                                break;
                            }
                        }
                        off += len;
                        r.BytesWritten = off;
                        Progress("Writing", off, size, sw, r, false);
                    }
                    FlushFileBuffers(h);
                    Progress("Writing", r.BytesWritten, size, sw, r, true);
                    Console.WriteLine();
                    r.WriteMBps = r.BytesWritten / 1048576.0 / Math.Max(sw.Elapsed.TotalSeconds, 0.001);

                    // verify pass
                    if (!r.DeviceLost && !userStopped)
                    {
                        long limit = r.BytesWritten;
                        sw.Reset(); sw.Start(); _last = -10000;
                        consec = 0; off = 0;
                        bool anyAlias;
                        while (off < limit)
                        {
                            if (UserAbort()) { Abort(r, "Stopped by user (Esc) during verify pass."); break; }
                            int len = (int)Math.Min((long)Chunk, limit - off);
                            int words = len / 8;
                            if (!ReadAt(h, off, buf, len, out err))
                            {
                                if (IsFatal(err)) { r.DeviceLost = true; Abort(r, "Device stopped responding (Win32 error " + err + ") while verifying at byte " + off + "."); break; }
                                r.BadSectors += len / sector; r.SectorsTested += len / sector; MarkBad(r, off);
                                if (++consec >= MaxConsecutiveChunkFailures) { Abort(r, "Reads keep failing during verify; stopping."); break; }
                            }
                            else
                            {
                                consec = 0;
                                Marshal.Copy(buf, got, 0, words);
                                Fill(pat, words, off, seed, wps);
                                Compare(r, pat, got, words, off, seed, wps, sector, size, out anyAlias);
                            }
                            off += len;
                            r.BytesVerified = off;
                            Progress("Verifying", off, limit, sw, r, false);
                        }
                        Progress("Verifying", r.BytesVerified, limit, sw, r, true);
                        Console.WriteLine();
                        r.ReadMBps = r.BytesVerified / 1048576.0 / Math.Max(sw.Elapsed.TotalSeconds, 0.001);
                    }
                }
            }
            finally { Free(buf); }
            return r;
        }

        // ------------------------------------------------------------ quick probe (destructive)
        // Writes 64 KiB blocks on a power-of-two grid across the whole reported size (>= 256 points),
        // then reads them back. Catches cards that error out, return junk, or wrap high addresses
        // onto low ones (when the wrap lands on another probe). Not a substitute for the full test.
        public static TestResult QuickProbe(int disk, long size, int sector, ulong seed)
        {
            const int Block = 64 * 1024;
            TestResult r = new TestResult(); r.Size = size;
            int wps = sector / 8, words = Block / 8;
            long step = 1L << 30;
            while (step > Block && size / step < 256) step >>= 1;
            List<long> offs = new List<long>();
            for (long o = 0; o + Block <= size; o += step) offs.Add(o);
            long lastOff = (size - Block) / sector * sector;
            if (offs.Count == 0 || offs[offs.Count - 1] != lastOff) offs.Add(lastOff);
            r.ProbeOffsets = offs.ToArray();
            r.ProbeStatus = new int[offs.Count];

            IntPtr buf = Alloc(Block);
            long[] pat = new long[words];
            long[] got = new long[words];
            try
            {
                using (SafeFileHandle h = Open(disk, true))
                {
                    Stopwatch sw = Stopwatch.StartNew(); _last = -10000;
                    int err;
                    for (int i = 0; i < offs.Count; i++)
                    {
                        if (UserAbort()) { Abort(r, "Stopped by user (Esc)."); return r; }
                        Fill(pat, words, offs[i], seed, wps);
                        Marshal.Copy(pat, 0, buf, words);
                        if (!WriteAt(h, offs[i], buf, Block, out err))
                        {
                            if (IsFatal(err)) { r.DeviceLost = true; Abort(r, "Device stopped responding (Win32 error " + err + ") while writing probe at byte " + offs[i] + "."); return r; }
                            r.ProbeStatus[i] = 1; r.BadSectors += Block / sector; MarkBad(r, offs[i]);
                        }
                        r.BytesWritten += Block;
                        Progress("Writing", (long)(i + 1) * Block, (long)offs.Count * Block, sw, r, false);
                    }
                    FlushFileBuffers(h);
                    Progress("Writing", (long)offs.Count * Block, (long)offs.Count * Block, sw, r, true);
                    Console.WriteLine();

                    sw.Reset(); sw.Start(); _last = -10000;
                    for (int i = 0; i < offs.Count; i++)
                    {
                        if (UserAbort()) { Abort(r, "Stopped by user (Esc)."); return r; }
                        if (!ReadAt(h, offs[i], buf, Block, out err))
                        {
                            if (IsFatal(err)) { r.DeviceLost = true; Abort(r, "Device stopped responding (Win32 error " + err + ") while reading probe at byte " + offs[i] + "."); return r; }
                            if (r.ProbeStatus[i] == 0) r.ProbeStatus[i] = 2;
                            r.BadSectors += Block / sector; MarkBad(r, offs[i]);
                        }
                        else
                        {
                            Marshal.Copy(buf, got, 0, words);
                            Fill(pat, words, offs[i], seed, wps);
                            bool alias;
                            int bad = Compare(r, pat, got, words, offs[i], seed, wps, sector, size, out alias);
                            if (bad > 0 && r.ProbeStatus[i] == 0) r.ProbeStatus[i] = alias ? 4 : 3;
                        }
                        r.BytesVerified += Block;
                        Progress("Verifying", (long)(i + 1) * Block, (long)offs.Count * Block, sw, r, false);
                    }
                    Progress("Verifying", (long)offs.Count * Block, (long)offs.Count * Block, sw, r, true);
                    Console.WriteLine();
                }
            }
            finally { Free(buf); }
            return r;
        }
    }
}
'@
if (-not ('DriveDoctor.RawDisk' -as [type])) { Add-Type -TypeDefinition $engine -Language CSharp }

# ---------------------------------------------------------------- helpers
function Write-Info([string]$m) { Write-Host "  $m" }
function Write-Good([string]$m) { Write-Host "  $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "  $m" -ForegroundColor Yellow }
function Write-Bad([string]$m) { Write-Host "  $m" -ForegroundColor Red }

function Format-Bytes([double]$b) {
    if ($b -ge 1e12) { return ('{0:N2} TB' -f ($b / 1e12)) }
    if ($b -ge 1e9) { return ('{0:N2} GB' -f ($b / 1e9)) }
    if ($b -ge 1e6) { return ('{0:N1} MB' -f ($b / 1e6)) }
    return ('{0:N0} bytes' -f $b)
}

function Get-SectorSize($d) {
    $s = [int]$d.LogicalSectorSize
    if ($s -lt 512 -or ($s % 512) -ne 0) { $s = 512 }
    return $s
}

function New-Seed {
    $b = New-Object byte[] 8
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($b); $rng.Dispose()
    return [BitConverter]::ToUInt64($b, 0)
}

function Get-DriveLetters([int]$n) {
    @(Get-Partition -DiskNumber $n -ErrorAction SilentlyContinue |
        ForEach-Object { [string]$_.DriveLetter } |
        Where-Object { $_ -match '^[A-Za-z]$' } |
        ForEach-Object { $_.ToUpper() })
}

function Get-CandidateDisks {
    @(Get-Disk | Where-Object { ($AllowedBusTypes -contains [string]$_.BusType) -and -not $_.IsBoot -and -not $_.IsSystem } |
        Sort-Object Number)
}

function Test-LargeFixed($d) {
    if ($AllowLargeFixed -or $d.Size -le $FixedMediaLimitBytes) { return $false }
    $wmi = Get-CimInstance Win32_DiskDrive -Filter "Index=$($d.Number)" -ErrorAction SilentlyContinue
    return -not ($wmi -and [string]$wmi.MediaType -match 'Removable')
}

function Assert-SafeDisk([int]$n) {
    $d = Get-Disk -Number $n -ErrorAction Stop
    if ($d.IsBoot -or $d.IsSystem) { throw "Disk $n is a boot/system disk. Refusing." }
    if ($AllowedBusTypes -notcontains [string]$d.BusType) { throw "Disk $n has bus type '$($d.BusType)', not USB/SD/MMC. Refusing." }
    if (Test-LargeFixed $d) { throw "Disk $n ($($d.FriendlyName), $(Format-Bytes $d.Size)) reports fixed media and is larger than 256 GiB: this looks like an external HDD/SSD, not a card or thumb drive. Refusing. (Start with -AllowLargeFixed to override.)" }
    $letters = @(Get-DriveLetters $n)
    $sys = $env:SystemDrive.Substring(0, 1).ToUpper()
    if ($letters -contains $sys) { throw "Disk $n holds the Windows drive (${sys}:). Refusing." }
    if ($PSScriptRoot -match '^([A-Za-z]):') {
        $here = $Matches[1].ToUpper()
        if ($letters -contains $here) { throw "DriveDoctor is running from disk $n (${here}:). Copy it to another drive first." }
    }
    $pf = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.Substring(0, 1).ToUpper() })
    foreach ($p in $pf) { if ($letters -contains $p) { throw "Disk $n holds a page file (${p}:). Refusing." } }
    return $d
}

function Test-SameDisk($before) {
    # guards against the card being swapped / disk numbers shifting between selection and action
    $now = Get-Disk -Number $before.Number -ErrorAction SilentlyContinue
    if (-not $now) { return $false }
    return ($now.FriendlyName -eq $before.FriendlyName -and [string]$now.SerialNumber -eq [string]$before.SerialNumber -and $now.Size -eq $before.Size)
}

function Show-Disks {
    $disks = Get-CandidateDisks
    if ($disks.Count -eq 0) {
        Write-Warn 'No USB/SD/MMC disks found. Insert the card/drive, wait a few seconds, try again.'
        Write-Warn '(Some PCIe card readers report as SCSI/NVMe; DriveDoctor deliberately ignores those - use a USB reader.)'
        return @()
    }
    $rows = foreach ($d in $disks) {
        [pscustomobject]@{
            Disk     = $d.Number
            Name     = $d.FriendlyName
            Bus      = [string]$d.BusType
            Size     = $(if ($d.Size -gt 0) { Format-Bytes $d.Size } else { 'no media' })
            Style    = $d.PartitionStyle
            Status   = $d.OperationalStatus
            Health   = $d.HealthStatus
            ReadOnly = $d.IsReadOnly
            Offline  = $d.IsOffline
            Letters  = ((Get-DriveLetters $d.Number | ForEach-Object { "${_}:" }) -join ' ')
        }
    }
    $rows | Format-Table -AutoSize | Out-Host
    foreach ($d in $disks) {
        if ($d.Size -gt 0 -and (Test-LargeFixed $d)) { Write-Warn "Disk $($d.Number) reports fixed media and is over 256 GiB (external HDD/SSD?): DriveDoctor will refuse it." }
    }
    return $disks
}

function Select-TargetDisk {
    $disks = @(Show-Disks)
    if ($disks.Count -eq 0) { return $null }
    $ans = Read-Host '  Disk number (blank = cancel)'
    if ([string]::IsNullOrWhiteSpace($ans)) { return $null }
    $n = 0
    if (-not [int]::TryParse($ans.Trim(), [ref]$n)) { Write-Warn 'Not a number.'; return $null }
    if (-not ($disks | Where-Object { $_.Number -eq $n })) { Write-Bad "Disk $n is not in the removable list. Refusing."; return $null }
    try { $d = Assert-SafeDisk $n } catch { Write-Bad $_.Exception.Message; return $null }
    if ($d.Size -le 0) { Write-Warn "Disk $n has no media."; return $null }
    return $d
}

function Confirm-Destructive($d, [string]$action) {
    Write-Host ''
    Write-Host "  !!! $action ERASES EVERYTHING on this disk !!!" -ForegroundColor Red
    Write-Host ('  Disk {0}: {1}  [{2}]  {3}  serial {4}' -f $d.Number, $d.FriendlyName, $d.BusType, (Format-Bytes $d.Size), $d.SerialNumber) -ForegroundColor Red
    $letters = @(Get-DriveLetters $d.Number)
    foreach ($L in $letters) {
        $v = Get-Volume -DriveLetter $L -ErrorAction SilentlyContinue
        if ($v) { Write-Host ('  Mounted as {0}:  {1}  ''{2}''  {3} used of {4}' -f $L, $v.FileSystem, $v.FileSystemLabel, (Format-Bytes ($v.Size - $v.SizeRemaining)), (Format-Bytes $v.Size)) -ForegroundColor Red }
        else { Write-Host "  Mounted as ${L}:" -ForegroundColor Red }
    }
    if ($d.Size -gt $LargeDiskWarnBytes) {
        Write-Warn 'This disk reports more than 512 GB. That is unusual for an SD card or thumb drive: it may be an'
        Write-Warn 'external SSD/HDD, or a fake-capacity card (those often claim 1-2 TB). Double-check before continuing.'
    }
    $expect = "ERASE $($d.Number)"
    $ans = Read-Host "  Type '$expect' to continue"
    if ($ans.Trim() -ne $expect) { Write-Warn 'Cancelled.'; return $false }
    if (-not (Test-SameDisk $d)) { Write-Bad 'The disk changed since it was selected (removed or swapped). Cancelled.'; return $false }
    return $true
}

function Invoke-DiskPart([string[]]$Lines) {
    $f = Join-Path $env:TEMP ('dd_diskpart_{0}.txt' -f [guid]::NewGuid())
    Set-Content -Path $f -Value $Lines -Encoding Ascii
    try {
        $out = & diskpart.exe /s $f
        $code = $LASTEXITCODE
    } finally { Remove-Item $f -ErrorAction SilentlyContinue }
    foreach ($l in $out) { if ($l -and $l.Trim()) { Write-Host "    $l" -ForegroundColor DarkGray } }
    return $code
}

function Clear-DiskForRawAccess($d) {
    try { Assert-SafeDisk $d.Number | Out-Null } catch { Write-Bad $_.Exception.Message; return $false }
    Write-Info 'Removing partitions (diskpart clean)...'
    $code = Invoke-DiskPart @("select disk $($d.Number)", 'attributes disk clear readonly noerr', 'online disk noerr', 'clean')
    Start-Sleep -Seconds 2
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $d2 = Get-Disk -Number $d.Number -ErrorAction SilentlyContinue
    if ($code -ne 0 -or -not $d2 -or $d2.IsReadOnly) {
        Write-Bad "Could not clean the disk (diskpart exit code $code)."
        Write-Warn 'If it reports write protection: check the SD lock switch (also on microSD adapters) and try option 3.'
        Write-Warn 'If it stays write-protected, the controller has locked the flash read-only (typical end of life). Replace it.'
        return $false
    }
    return $true
}

function Get-SeqVerdict($r, [int]$sector) {
    # Classifies a full test result. Returns @{ Kind; UsableBytes }
    $failed = 0
    if ($r.BadSectors + $r.MismatchSectors -eq 0 -and -not $r.Aborted) { return @{ Kind = 'pass'; UsableBytes = $r.Size } }
    $totalSectors = [math]::Floor($r.Size / $sector)
    $failed = $totalSectors - $r.GoodSectors
    if ($r.AliasSectors -gt 0) { return @{ Kind = 'fake-wrap'; UsableBytes = [long]$r.GoodSectors * $sector } }
    if ($r.FirstBadOffset -ge 0) {
        $tailSectors = [math]::Floor(($r.Size - $r.FirstBadOffset) / $sector)
        if ($tailSectors -gt 0 -and $failed -ge 0.9 * $tailSectors) { return @{ Kind = 'fake-tail'; UsableBytes = [long]$r.FirstBadOffset } }
        return @{ Kind = 'scattered'; UsableBytes = 0 }
    }
    return @{ Kind = 'incomplete'; UsableBytes = 0 }
}

function Show-TestResult($r, [string]$name, [int]$sector) {
    Write-Host ''
    Write-Host "  ---- $name result ----" -ForegroundColor Cyan
    Write-Info ('Reported size        : {0}  ({1:N0} bytes)' -f (Format-Bytes $r.Size), $r.Size)
    if ($r.BytesWritten -gt 0) { Write-Info ('Written              : {0}' -f (Format-Bytes $r.BytesWritten)) }
    Write-Info ('Read back            : {0}' -f (Format-Bytes $r.BytesVerified))
    if ($r.WriteMBps -gt 0) { Write-Info ('Write speed          : {0:N1} MiB/s' -f $r.WriteMBps) }
    if ($r.ReadMBps -gt 0) { Write-Info ('Read speed           : {0:N1} MiB/s' -f $r.ReadMBps) }
    Write-Info ('I/O error sectors    : {0:N0}' -f $r.BadSectors)
    if ($r.MismatchSectors -gt 0 -or $r.BytesWritten -gt 0) { Write-Info ('Wrong-data sectors   : {0:N0}  (of which {1:N0} hold data written for another address)' -f $r.MismatchSectors, $r.AliasSectors) }
    if ($r.FirstBadOffset -ge 0) { Write-Info ('First failure at     : byte {0:N0}  ({1})' -f $r.FirstBadOffset, (Format-Bytes $r.FirstBadOffset)) }
    if ($r.Aborted) { Write-Warn "Stopped early: $($r.AbortReason)" }
}

function Read-FileSystemChoice([long]$bytes) {
    $default = $(if ($bytes -le 32GB) { 'FAT32' } else { 'exFAT' })
    Write-Info '1) FAT32  - widest compatibility, 4 GB max file size; Windows only formats it up to 32 GB'
    Write-Info '2) exFAT  - standard for SDXC (>32 GB), cameras, phones, consoles'
    Write-Info '3) NTFS   - Windows only'
    $a = Read-Host "  File system [default $default]"
    switch ($a.Trim()) { '1' { $fs = 'FAT32' } '2' { $fs = 'exFAT' } '3' { $fs = 'NTFS' } default { $fs = $default } }
    if ($fs -eq 'FAT32' -and $bytes -gt 32GB) {
        Write-Warn 'Windows refuses FAT32 above 32 GB; using exFAT instead. (Need FAT32 on a big card? Use a third-party formatter.)'
        $fs = 'exFAT'
    }
    return $fs
}

function Invoke-Reformat {
    param($Disk = $null, [long]$MaxBytes = 0)
    $d = $Disk
    if (-not $d) {
        $d = Select-TargetDisk
        if (-not $d) { return }
        if (-not (Confirm-Destructive $d 'Wipe + repartition + format')) { return }
    }
    try { Assert-SafeDisk $d.Number | Out-Null } catch { Write-Bad $_.Exception.Message; return }
    $partBytes = $(if ($MaxBytes -gt 0) { [math]::Min($MaxBytes, [long]$d.Size) } else { [long]$d.Size })
    $fs = Read-FileSystemChoice $partBytes
    $label = Read-Host '  Volume label (max 11 chars, blank = USBDRIVE)'
    $label = ($label -replace '[^A-Za-z0-9_\- ]', '').Trim()
    if ($label.Length -gt 11) { $label = $label.Substring(0, 11) }
    if (-not $label) { $label = 'USBDRIVE' }

    $create = 'create partition primary align=4096'
    if ($MaxBytes -gt 0) {
        $mb = [math]::Floor($MaxBytes / 1MB)
        $create = "create partition primary size=$mb align=4096"
        Write-Warn ("Partition limited to {0:N0} MiB (verified-good region)." -f $mb)
    }
    $lines = @(
        "select disk $($d.Number)",
        'attributes disk clear readonly noerr',
        'online disk noerr',
        'clean',
        'convert mbr',
        $create,
        "format fs=$($fs.ToLower()) label=`"$label`" quick",
        'assign'
    )
    Write-Info "Partitioning and formatting as $fs..."
    $code = Invoke-DiskPart $lines
    Start-Sleep -Seconds 2
    Update-HostStorageCache -ErrorAction SilentlyContinue
    if ($code -ne 0) {
        Write-Bad "diskpart failed (exit code $code). See the output above."
        Write-Warn 'Write protected -> lock switch / option 3. "I/O device error" or timeouts -> failing flash or controller.'
        return
    }
    Write-Good 'Format complete.'
    Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue | Get-Volume -ErrorAction SilentlyContinue |
        Select-Object DriveLetter, FileSystemLabel, FileSystem, @{n = 'Size'; e = { Format-Bytes $_.Size } }, HealthStatus |
        Format-Table -AutoSize | Out-Host
}

# ---------------------------------------------------------------- menu actions
function Show-DiskDetails {
    $d = Select-TargetDisk
    if (-not $d) { return }
    $d | Select-Object Number, FriendlyName, Manufacturer, Model, SerialNumber, BusType,
        @{n = 'Size'; e = { '{0}  ({1:N0} bytes)' -f (Format-Bytes $_.Size), $_.Size } },
        LogicalSectorSize, PhysicalSectorSize, PartitionStyle, OperationalStatus, HealthStatus,
        IsReadOnly, IsOffline, OfflineReason | Format-List | Out-Host

    $parts = @(Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue)
    if ($parts.Count -eq 0) { Write-Warn 'No partitions: the disk is blank/RAW or its partition table is unreadable. Option 8 rebuilds it.' }
    else {
        $rows = foreach ($p in $parts) {
            $v = $null
            try { $v = $p | Get-Volume -ErrorAction Stop } catch { }
            [pscustomobject]@{
                Part       = $p.PartitionNumber
                Letter     = [string]$p.DriveLetter -replace '\x00', ''
                Offset     = $p.Offset
                Aligned4M  = (($p.Offset % 4MB) -eq 0)
                Size       = Format-Bytes $p.Size
                FileSystem = $(if ($v) { $(if ($v.FileSystem) { $v.FileSystem } else { 'RAW' }) } else { '?' })
                Label      = $(if ($v) { $v.FileSystemLabel } else { '' })
                Free       = $(if ($v) { Format-Bytes $v.SizeRemaining } else { '' })
                VolHealth  = $(if ($v) { $v.HealthStatus } else { '' })
            }
        }
        $rows | Format-Table -AutoSize | Out-Host
        if ($rows | Where-Object { -not $_.Aligned4M }) { Write-Warn 'A partition is not 4 MiB aligned. Flash erase blocks are typically 4 MiB; reformatting (option 8) fixes this and can improve write speed.' }
        if ($rows | Where-Object { $_.FileSystem -eq 'RAW' }) { Write-Warn 'RAW volume: the file system is unreadable. Option 4 may fix minor damage; otherwise option 8.' }
    }

    $total = [long]$d.Size
    if ($d.Size -gt 0 -and $parts.Count) {
        $used = ($parts | Measure-Object -Property Size -Sum).Sum
        if ($used -lt 0.9 * $total) { Write-Warn ('Partitions cover only {0} of {1}. Option 8 reclaims the rest.' -f (Format-Bytes $used), (Format-Bytes $total)) }
    }

    # reliability counters (rarely exposed by USB/SD)
    try {
        $pd = Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.DeviceId -eq [string]$d.Number }
        $rc = $pd | Get-StorageReliabilityCounter -ErrorAction Stop
        $vals = $rc | Select-Object ReadErrorsTotal, ReadErrorsUncorrected, WriteErrorsTotal, WriteErrorsUncorrected, Temperature, Wear, PowerOnHours
        $hasAny = $false
        foreach ($p in $vals.PSObject.Properties) { if ($null -ne $p.Value) { $hasAny = $true } }
        if ($hasAny) { Write-Info 'Reliability counters:'; $vals | Format-List | Out-Host }
        else { Write-Info 'Reliability/SMART counters: not exposed (normal for SD cards and most USB sticks).' }
    } catch { Write-Info 'Reliability/SMART counters: not exposed (normal for SD cards and most USB sticks).' }

    # registry write-protect policy
    $wp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' -Name WriteProtect -ErrorAction SilentlyContinue).WriteProtect
    if ($wp -eq 1) { Write-Bad 'Registry policy StorageDevicePolicies\WriteProtect = 1: Windows blocks writes to ALL USB storage. Option 3 can clear it.' }

    # recent disk driver errors for this disk number
    try {
        $since = (Get-Date).AddDays(-7)
        $pattern = "\\Harddisk$($d.Number)\\"
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'disk'; StartTime = $since } -ErrorAction Stop |
                Where-Object { $_.Message -match $pattern })
        if ($ev.Count) {
            Write-Warn ("{0} disk driver events in the last 7 days mention Harddisk{1} (disk numbers can be reused by other devices):" -f $ev.Count, $d.Number)
            $ev | Group-Object Id | ForEach-Object {
                $g = $_
                $desc = switch ([int]$g.Name) { 7 { 'bad block' } 11 { 'controller error' } 51 { 'error during paging' } 153 { 'I/O retried' } 154 { 'I/O failed (hardware)' } 157 { 'surprise removal' } default { '' } }
                Write-Info ('  event {0,-4} x{1,-5} {2}' -f $g.Name, $g.Count, $desc)
            }
        } else { Write-Good "No disk driver errors logged for Harddisk$($d.Number) in the last 7 days." }
    } catch { Write-Good "No disk driver errors logged for Harddisk$($d.Number) in the last 7 days." }

    # verdict hints
    Write-Host ''
    if ($d.IsReadOnly) { Write-Bad 'Disk is READ-ONLY. Try option 3. If it will not clear: lock switch, or the controller has locked itself (end of life).' }
    if ($d.IsOffline) { Write-Warn "Disk is OFFLINE ($($d.OfflineReason)). Option 3 brings it online." }
    if ([string]$d.PartitionStyle -eq 'RAW') { Write-Warn 'Disk is uninitialized (RAW). Option 8 partitions and formats it.' }
    if ($d.Size -gt $LargeDiskWarnBytes) { Write-Warn 'Reported size is very large for removable flash; run option 6 or 7 to rule out a fake-capacity device.' }
}

function Clear-ReadOnly {
    $d = Select-TargetDisk
    if (-not $d) { return }
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies'
    $wp = (Get-ItemProperty $key -Name WriteProtect -ErrorAction SilentlyContinue).WriteProtect
    if ($wp -eq 1) {
        $a = Read-Host '  Registry policy WriteProtect=1 blocks writes to ALL USB storage. Set it to 0? (y/n)'
        if ($a -match '^[Yy]') { Set-ItemProperty -Path $key -Name WriteProtect -Value 0; Write-Good 'Policy cleared. Unplug and reinsert the drive afterwards.' }
    }
    try { Set-Disk -Number $d.Number -IsOffline $false -ErrorAction Stop } catch { }
    try { Set-Disk -Number $d.Number -IsReadOnly $false -ErrorAction Stop } catch { Write-Info "Set-Disk: $($_.Exception.Message)" }
    $lines = @("select disk $($d.Number)", 'attributes disk clear readonly noerr', 'online disk noerr')
    foreach ($L in (Get-DriveLetters $d.Number)) {
        $lines += "select volume $L"
        $lines += 'attributes volume clear readonly noerr'
        $lines += 'attributes volume clear hidden noerr'
    }
    Invoke-DiskPart $lines | Out-Null
    Start-Sleep -Seconds 1
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $d2 = Get-Disk -Number $d.Number
    if ($d2.IsReadOnly) {
        Write-Bad 'Still read-only. Causes, most likely first:'
        Write-Info ' - SD / microSD-adapter lock switch is in the LOCK position (slide it toward the contacts).'
        Write-Info ' - The card controller has permanently switched to read-only. Flash controllers do this at end of life'
        Write-Info '   or after detecting too many failed blocks. Software cannot undo it; copy anything you need and replace it.'
        return
    }
    Write-Good 'Disk read-only flag is clear.'
    foreach ($L in (Get-DriveLetters $d.Number)) {
        $t = "${L}:\dd_write_test_$([guid]::NewGuid().ToString('N')).tmp"
        try {
            Set-Content -Path $t -Value 'DriveDoctor write test' -ErrorAction Stop
            Remove-Item $t -ErrorAction Stop
            Write-Good "Write test on ${L}: OK."
        } catch { Write-Bad "Write test on ${L}: failed - $($_.Exception.Message)" }
    }
}

function Repair-FileSystemMenu {
    $d = Select-TargetDisk
    if (-not $d) { return }
    $letters = @(Get-DriveLetters $d.Number)
    if ($letters.Count -eq 0) { Write-Warn 'No mounted volumes. If the disk shows as RAW, its file system is gone: use option 8.'; return }
    foreach ($L in $letters) {
        Write-Info "chkdsk ${L}: /f /x"
        & chkdsk.exe "${L}:" /f /x
        switch ($LASTEXITCODE) {
            0 { Write-Good "${L}: no errors found." }
            1 { Write-Good "${L}: errors found and fixed." }
            2 { Write-Good "${L}: cleanup performed, no errors." }
            default { Write-Bad "${L}: chkdsk could not check or fix the volume (exit $LASTEXITCODE). Reformat with option 8." }
        }
    }
}

function Invoke-SurfaceScan {
    $d = Select-TargetDisk
    if (-not $d) { return }
    $ss = Get-SectorSize $d
    Write-Info ('Reading all {0} - nothing is written. Press Esc to stop.' -f (Format-Bytes $d.Size))
    $r = [DriveDoctor.RawDisk]::ReadScan([int]$d.Number, [long]$d.Size, $ss)
    Show-TestResult $r 'Read surface scan' $ss
    if ($r.BadSectors -eq 0 -and -not $r.Aborted) { Write-Good 'PASS: every sector is readable.' }
    elseif ($r.BadSectors -gt 0) {
        Write-Bad ('FAIL: {0:N0} unreadable sectors. Flash with read errors keeps degrading; a full write test (7)' -f $r.BadSectors)
        Write-Bad 'can show whether the controller remaps them, but plan to replace this card.'
    }
    if ($r.ReadMBps -gt 0 -and $r.ReadMBps -lt 5 -and -not $r.Aborted) { Write-Warn 'Very low read speed: worn flash, a USB 1.1 port/hub, or a poor reader.' }
}

function Invoke-QuickProbe {
    $d = Select-TargetDisk
    if (-not $d) { return }
    if (-not (Confirm-Destructive $d 'Quick fake-capacity probe')) { return }
    if (-not (Clear-DiskForRawAccess $d)) { return }
    $ss = Get-SectorSize $d
    $r = [DriveDoctor.RawDisk]::QuickProbe([int]$d.Number, [long]$d.Size, $ss, (New-Seed))
    Show-TestResult $r 'Quick probe' $ss
    $n = $r.ProbeStatus.Length
    $badIdx = @(0..($n - 1) | Where-Object { $r.ProbeStatus[$_] -ne 0 })
    if ($r.DeviceLost) { Write-Bad 'The device dropped off the bus during the probe. Typical of fakes and dying controllers.' }
    elseif ($badIdx.Count -eq 0 -and -not $r.Aborted) {
        Write-Good ("PASS: all {0} probe points across the full {1} read back correctly." -f $n, (Format-Bytes $r.Size))
        Write-Info 'Not a crude fake. Option 7 tests every sector if you want certainty.'
    } elseif ($badIdx.Count -gt 0) {
        $first = $badIdx[0]
        $counts = $r.ProbeStatus | Group-Object | Where-Object { $_.Name -ne '0' } | ForEach-Object {
            $g = $_
            $label = switch ($g.Name) { '1' { 'write error' } '2' { 'read error' } '3' { 'wrong data' } '4' { 'data from another address' } }
            "$($g.Count) $label"
        }
        Write-Bad ("FAIL: {0} of {1} probe points bad ({2})." -f $badIdx.Count, $n, ($counts -join ', '))
        if ($r.AliasSectors -gt 0) {
            Write-Bad ('Address wraparound detected (period {0}). This is a FAKE-CAPACITY device; real capacity is about {0} or less.' -f (Format-Bytes $r.AliasPeriod))
        } elseif ($badIdx.Count -eq ($n - $first)) {
            $goodTo = $(if ($first -gt 0) { $r.ProbeOffsets[$first - 1] } else { 0 })
            Write-Bad ('Everything from {0} upward fails; the last good probe is at {1}. Real capacity is about {1} - likely a FAKE-CAPACITY device.' -f (Format-Bytes $r.ProbeOffsets[$first]), (Format-Bytes $goodTo))
        } else {
            Write-Bad 'Failures are scattered rather than a clean upper region: defective/worn flash rather than a fake.'
        }
        Write-Warn 'Run option 7 next: it measures the exact usable capacity and can create a safe, smaller partition.'
        Invoke-DiskPart @("select disk $($d.Number)", 'clean') | Out-Null
        return
    }
    $a = Read-Host '  The disk is now blank. Partition and format it now? (Y/n)'
    if ($a -notmatch '^[Nn]') { Invoke-Reformat -Disk (Get-Disk -Number $d.Number) }
    else { Invoke-DiskPart @("select disk $($d.Number)", 'clean') | Out-Null; Write-Info 'Left blank (uninitialized).' }
}

function Invoke-FullTest {
    $d = Select-TargetDisk
    if (-not $d) { return }
    Write-Warn ('This writes and then reads all {0}. At 20 MB/s that is roughly {1:N0} minutes per pass, two passes.' -f (Format-Bytes $d.Size), ($d.Size / 20e6 / 60))
    if (-not (Confirm-Destructive $d 'Full write + verify test')) { return }
    if (-not (Clear-DiskForRawAccess $d)) { return }
    $ss = Get-SectorSize $d
    $r = [DriveDoctor.RawDisk]::WriteVerify([int]$d.Number, [long]$d.Size, $ss, (New-Seed))
    Show-TestResult $r 'Full write + verify' $ss
    $v = Get-SeqVerdict $r $ss
    $limit = 0
    switch ($v.Kind) {
        'pass' { Write-Good 'PASS: every sector held the data written to it. The full capacity is genuine and usable.' }
        'fake-wrap' {
            Write-Bad ('FAKE CAPACITY: high addresses wrap onto low ones (period {0}).' -f (Format-Bytes $r.AliasPeriod))
            Write-Bad ('Real, usable capacity is about {0} of the {1} reported.' -f (Format-Bytes $v.UsableBytes), (Format-Bytes $r.Size))
            $limit = [long]($v.UsableBytes * 0.98)
        }
        'fake-tail' {
            Write-Bad ('Everything from {0} upward fails. Usable capacity is about {0} of the {1} reported.' -f (Format-Bytes $v.UsableBytes), (Format-Bytes $r.Size))
            Write-Bad 'If that is far below the label, the device is a FAKE-CAPACITY device.'
            $limit = [long]($v.UsableBytes * 0.98)
        }
        'scattered' {
            Write-Bad ('FAIL: {0:N0} bad sectors scattered across the device. The flash is defective or worn out; replace it.' -f ($r.BadSectors + $r.MismatchSectors))
        }
        default { Write-Warn 'Test did not complete; no verdict.' }
    }
    if ($r.DeviceLost) { Write-Bad 'The device dropped off the bus during the test. Reinsert it before doing anything else.'; return }

    if ($limit -gt 8MB) {
        $a = Read-Host ('  Create a partition limited to the verified-good {0}? (Y/n)' -f (Format-Bytes $limit))
        if ($a -notmatch '^[Nn]') { Invoke-Reformat -Disk (Get-Disk -Number $d.Number) -MaxBytes $limit; return }
    } elseif ($v.Kind -eq 'pass') {
        $a = Read-Host '  The disk holds test data only. Partition and format it now? (Y/n)'
        if ($a -notmatch '^[Nn]') { Invoke-Reformat -Disk (Get-Disk -Number $d.Number); return }
    } elseif ($v.Kind -eq 'scattered') {
        $a = Read-Host '  Format it anyway (not recommended - expect silent data corruption)? (y/N)'
        if ($a -match '^[Yy]') { Invoke-Reformat -Disk (Get-Disk -Number $d.Number); return }
    }
    Invoke-DiskPart @("select disk $($d.Number)", 'clean') | Out-Null
    Write-Info 'Disk left blank (uninitialized).'
}

# ---------------------------------------------------------------- main loop
Write-Host ''
Write-Host "  DriveDoctor $Version - removable drive diagnostics and repair" -ForegroundColor Cyan
Write-Host "  Only USB / SD / MMC disks are listed; system and boot disks are always refused." -ForegroundColor DarkCyan
Write-Host "  Log: $LogFile" -ForegroundColor DarkGray

:menu while ($true) {
    Write-Host ''
    Write-Host '  1  List removable drives'
    Write-Host '  2  Details and health report'
    Write-Host '  3  Clear read-only / bring online'
    Write-Host '  4  Repair file system (chkdsk /f)           keeps data'
    Write-Host '  5  Read surface scan                         keeps data'
    Write-Host '  6  Quick fake-capacity probe (~1 min)        ERASES' -ForegroundColor Yellow
    Write-Host '  7  Full write + verify test (slow)           ERASES' -ForegroundColor Yellow
    Write-Host '  8  Wipe, repartition and format              ERASES' -ForegroundColor Yellow
    Write-Host '  Q  Quit'
    $c = Read-Host '  Choice'
    if ($null -eq $c) { $c = '' }
    try {
        switch ($c.Trim().ToUpper()) {
            '1' { Show-Disks | Out-Null }
            '2' { Show-DiskDetails }
            '3' { Clear-ReadOnly }
            '4' { Repair-FileSystemMenu }
            '5' { Invoke-SurfaceScan }
            '6' { Invoke-QuickProbe }
            '7' { Invoke-FullTest }
            '8' { Invoke-Reformat }
            'Q' { break menu }
            default { }
        }
    } catch {
        Write-Bad "Error: $($_.Exception.Message)"
    }
}
try { Stop-Transcript | Out-Null } catch { }
