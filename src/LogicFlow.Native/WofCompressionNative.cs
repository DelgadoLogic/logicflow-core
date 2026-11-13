// LogicFlow.Native — Windows Overlay Filter (WOF / CompactOS) Interop Layer
// Proprietary implementation by DelgadoLogic.Tech
// Direct Win32/NT kernel bindings for wofutil.dll, kernel32.dll, and NTFS filesystem control codes.

using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace LogicFlow.Native;

/// <summary>
/// Execution status classification for WOF compression operations.
/// </summary>
public enum WofCompressionStatus
{
    Success,
    SkippedNotBeneficial,
    SkippedSmallFile,
    SkippedLocked,
    SkippedAccessDenied,
    SkippedAlreadyCompressed,
    Error
}

/// <summary>
/// Structured result container returned by WOF compression methods.
/// </summary>
public sealed record WofCompressionResult
{
    public bool Success { get; init; }
    public WofCompressionStatus Status { get; init; }
    public string? FilePath { get; init; }
    public long OriginalSize { get; init; }
    public long CompressedSize { get; init; }
    public long SavedBytes { get; init; }
    public int ErrorCode { get; init; }
    public string? ErrorMessage { get; init; }
    public uint Algorithm { get; init; }
    public bool AlreadyCompressed { get; init; }
    public bool NonBeneficial { get; init; }

    public double CompressionRatio => OriginalSize > 0 ? (double)CompressedSize / OriginalSize : 1.0;
    public double SpaceSavedPercent => OriginalSize > 0 ? Math.Max(0.0, (1.0 - ((double)CompressedSize / OriginalSize)) * 100.0) : 0.0;

    public WofCompressionResult() { }

    public WofCompressionResult(
        bool success,
        long originalSize,
        long compressedSize,
        long savedBytes,
        int errorCode,
        string? errorMessage = null)
    {
        Success = success;
        OriginalSize = originalSize;
        CompressedSize = compressedSize;
        SavedBytes = savedBytes;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
        Status = success
            ? (savedBytes > 0 ? WofCompressionStatus.Success : WofCompressionStatus.SkippedNotBeneficial)
            : WofCompressionStatus.Error;
        NonBeneficial = errorCode == WofCompressionNative.HRESULT_COMPRESSION_NOT_BENEFICIAL ||
                        errorCode == WofCompressionNative.ERROR_COMPRESSION_NOT_BENEFICIAL;
    }

    public WofCompressionResult(
        bool success,
        WofCompressionStatus status,
        string filePath,
        long originalSize,
        long compressedSize,
        long savedBytes,
        int errorCode = 0,
        string? errorMessage = null)
    {
        Success = success;
        Status = status;
        FilePath = filePath;
        OriginalSize = originalSize;
        CompressedSize = compressedSize;
        SavedBytes = savedBytes;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
        NonBeneficial = status == WofCompressionStatus.SkippedNotBeneficial;
        AlreadyCompressed = status == WofCompressionStatus.SkippedAlreadyCompressed;
    }

    /// <summary>
    /// Enables direct boolean evaluation: if (WofCompressionNative.SetFileCompression(path, algo)) { ... }
    /// </summary>
    public static implicit operator bool(WofCompressionResult? result) => result is not null && result.Success;

    public static WofCompressionResult Succeeded(long originalSize, long compressedSize, uint algorithm, bool alreadyCompressed = false) =>
        new()
        {
            Success = true,
            Status = alreadyCompressed ? WofCompressionStatus.SkippedAlreadyCompressed : WofCompressionStatus.Success,
            OriginalSize = originalSize,
            CompressedSize = compressedSize,
            SavedBytes = Math.Max(0L, originalSize - compressedSize),
            Algorithm = algorithm,
            AlreadyCompressed = alreadyCompressed,
            ErrorCode = 0
        };

    public static WofCompressionResult NotBeneficial(long originalSize, uint algorithm) =>
        new()
        {
            Success = true,
            Status = WofCompressionStatus.SkippedNotBeneficial,
            OriginalSize = originalSize,
            CompressedSize = originalSize,
            SavedBytes = 0,
            Algorithm = algorithm,
            NonBeneficial = true,
            ErrorCode = WofCompressionNative.ERROR_COMPRESSION_NOT_BENEFICIAL,
            ErrorMessage = "Compression not beneficial (data entropy is too high or file does not compress)."
        };

    public static WofCompressionResult Skipped(long originalSize, string reason) =>
        new()
        {
            Success = false,
            Status = WofCompressionStatus.Error,
            OriginalSize = originalSize,
            CompressedSize = originalSize,
            SavedBytes = 0,
            ErrorCode = 0,
            ErrorMessage = reason
        };

    public static WofCompressionResult Failed(int errorCode, string errorMessage, long originalSize = 0) =>
        new()
        {
            Success = false,
            Status = WofCompressionStatus.Error,
            OriginalSize = originalSize,
            CompressedSize = originalSize,
            SavedBytes = 0,
            ErrorCode = errorCode,
            ErrorMessage = errorMessage
        };
}

/// <summary>
/// WOF external provider header.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct WOF_EXTERNAL_INFO
{
    public uint Version;  // WOF_CURRENT_VERSION = 1
    public uint Provider; // WOF_PROVIDER_FILE = 2
}

/// <summary>
/// Compression algorithm configuration for WOF file provider.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct WOF_FILE_COMPRESSION_INFO_V1
{
    public uint Algorithm; // FILE_PROVIDER_COMPRESSION_* (0..3)
    public uint Flags;     // Reserved (0)
}

/// <summary>
/// External backing info queried via FSCTL_GET_EXTERNAL_BACKING.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct FILE_PROVIDER_EXTERNAL_INFO_V1
{
    public uint Version;
    public uint Algorithm;
    public uint Flags;
}

/// <summary>
/// Combined header and backing info structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct WOF_FILE_PROVIDER_EXTERNAL_INFO
{
    public WOF_EXTERNAL_INFO ExternalInfo;
    public FILE_PROVIDER_EXTERNAL_INFO_V1 FileInfo;
}

/// <summary>
/// Low-level P/Invoke exports and safe managed wrappers for Windows Overlay Filter (wofutil.dll and kernel32.dll).
/// </summary>
public static class WofCompressionNative
{
    // ─── Provider & Version Constants ───────────────────────────────────────
    public const uint WOF_PROVIDER_UNKNOWN = 0;
    public const uint WOF_PROVIDER_WIM     = 1;
    public const uint WOF_PROVIDER_FILE    = 2;
    public const uint WOF_PROVIDER_CLOUD   = 3;

    public const uint WOF_CURRENT_VERSION          = 1;
    public const uint FILE_PROVIDER_CURRENT_VERSION = 1;

    // ─── CompactOS Compression Algorithms ───────────────────────────────────
    public const uint FILE_PROVIDER_COMPRESSION_XPRESS4K  = 0; // 4KB chunk XPRESS (Fastest)
    public const uint FILE_PROVIDER_COMPRESSION_LZX       = 1; // 32KB chunk LZX (Highest ratio)
    public const uint FILE_PROVIDER_COMPRESSION_XPRESS8K  = 2; // 8KB chunk XPRESS (Balanced default)
    public const uint FILE_PROVIDER_COMPRESSION_XPRESS16K = 3; // 16KB chunk XPRESS (High throughput)
    public const uint FILE_PROVIDER_COMPRESSION_MAXIMUM   = 4; // Algorithm boundary guard

    // Algorithm contract aliases matching PROJECT.md and DISPATCH.md
    public const uint ALGORITHM_XPRESS4K  = FILE_PROVIDER_COMPRESSION_XPRESS4K;
    public const uint ALGORITHM_LZX       = FILE_PROVIDER_COMPRESSION_LZX;
    public const uint ALGORITHM_XPRESS8K  = FILE_PROVIDER_COMPRESSION_XPRESS8K;
    public const uint ALGORITHM_XPRESS16K = FILE_PROVIDER_COMPRESSION_XPRESS16K;

    // ─── Filesystem Control Codes (FSCTL) ───────────────────────────────────
    // Canonical Windows SDK winioctl.h values:
    public const uint FSCTL_SET_EXTERNAL_BACKING    = 0x0009030C; // Function 195 (0xC3)
    public const uint FSCTL_GET_EXTERNAL_BACKING    = 0x00090310; // Function 196 (0xC4)
    public const uint FSCTL_DELETE_EXTERNAL_BACKING = 0x00090314; // Function 197 (0xC5)
    public const uint FSCTL_ENUM_EXTERNAL_BACKING   = 0x00090318; // Function 198 (0xC6)

    // Backwards-compatible aliases for legacy offset references:
    public const uint FSCTL_SET_EXTERNAL_BACKING_COMPAT    = 0x00090310;
    public const uint FSCTL_GET_EXTERNAL_BACKING_COMPAT    = 0x00090314;
    public const uint FSCTL_DELETE_EXTERNAL_BACKING_COMPAT = 0x00090318;
    public const uint FSCTL_SET_EXTERNAL_BACKING_ALT       = 0x00090310;
    public const uint FSCTL_GET_EXTERNAL_BACKING_ALT       = 0x00090314;
    public const uint FSCTL_DELETE_EXTERNAL_BACKING_ALT    = 0x00090318;

    // ─── Win32 & HRESULT Constants ──────────────────────────────────────────
    public const int S_OK = 0;
    public const int ERROR_SUCCESS = 0;
    public const int ERROR_FILE_NOT_FOUND = 2;
    public const int ERROR_ACCESS_DENIED = 5;
    public const int ERROR_SHARING_VIOLATION = 32;
    public const int ERROR_LOCK_VIOLATION = 33;
    public const int ERROR_INVALID_PARAMETER = 87;
    public const int ERROR_INSUFFICIENT_BUFFER = 122;
    public const int ERROR_NOT_EXTERNALLY_BACKED = 342;
    public const int ERROR_OBJECT_NOT_EXTERNALLY_BACKED = 342;
    public const int ERROR_COMPRESSION_NOT_BENEFICIAL = 344;
    public const int HRESULT_COMPRESSION_NOT_BENEFICIAL = unchecked((int)0x80070158);
    public const int HRESULT_OBJECT_NOT_EXTERNALLY_BACKED = unchecked((int)0x80070156);

    // ─── Win32 File Access Flags ────────────────────────────────────────────
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;

    // ─── P/Invoke Imports ───────────────────────────────────────────────────

    [DllImport("wofutil.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int WofSetFileDataLocation(
        SafeFileHandle FileHandle,
        uint Provider,
        IntPtr ExternalFileInfo,
        uint Length);

    [DllImport("wofutil.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int WofIsExternalFile(
        [MarshalAs(UnmanagedType.LPWStr)] string FilePath,
        out int IsExternalFile,
        out uint Provider,
        IntPtr ExternalFileInfo,
        ref uint BufferLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetCompressedFileSizeW")]
    public static extern uint GetCompressedFileSize(
        [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
        out uint lpFileSizeHigh);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetCompressedFileSizeW")]
    public static extern uint GetCompressedFileSizeW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
        out uint lpFileSizeHigh);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    // ─── Safe Managed Wrappers ──────────────────────────────────────────────

    /// <summary>
    /// Compresses a file on disk using Windows Overlay Filter CompactOS compression.
    /// Handles small files, non-beneficial data, ReadOnly attributes, and concurrency safely.
    /// </summary>
    /// <param name="path">Absolute path to the target file.</param>
    /// <param name="algorithm">Compression algorithm ID (0=XPRESS4K, 1=LZX, 2=XPRESS8K, 3=XPRESS16K).</param>
    /// <returns>A WofCompressionResult record containing operation telemetry.</returns>
    public static WofCompressionResult SetFileCompression(string path, uint algorithm = ALGORITHM_LZX)
    {
        if (string.IsNullOrWhiteSpace(path))
            return WofCompressionResult.Failed(ERROR_INVALID_PARAMETER, "File path cannot be null or empty.");

        if (!File.Exists(path))
            return WofCompressionResult.Failed(ERROR_FILE_NOT_FOUND, $"File does not exist: {path}");

        if (algorithm > FILE_PROVIDER_COMPRESSION_XPRESS16K)
            return WofCompressionResult.Failed(ERROR_INVALID_PARAMETER, $"Unsupported compression algorithm: {algorithm}");

        long originalSize;
        try
        {
            var fi = new FileInfo(path);
            originalSize = fi.Length;
        }
        catch (Exception ex)
        {
            return WofCompressionResult.Failed(-1, $"Failed to query file information: {ex.Message}");
        }

        // Zero-byte files cannot be compressed
        if (originalSize == 0)
        {
            return new WofCompressionResult(true, 0, 0, 0, 0, "Zero-byte file")
            {
                Algorithm = algorithm,
                FilePath = path
            };
        }

        // Check if already compressed with the desired algorithm
        if (IsFileCompressed(path, out uint currentAlgo, out _, out ulong currentCompressed))
        {
            if (currentAlgo == algorithm)
            {
                long saved = Math.Max(0L, originalSize - (long)currentCompressed);
                return new WofCompressionResult(true, WofCompressionStatus.SkippedAlreadyCompressed, path, originalSize, (long)currentCompressed, saved, 0, "Already compressed with target algorithm")
                {
                    Algorithm = algorithm,
                    AlreadyCompressed = true
                };
            }
        }

        // Temporarily strip ReadOnly attribute if present to ensure handle access
        bool wasReadOnly = false;
        FileAttributes originalAttrs = FileAttributes.Normal;
        try
        {
            originalAttrs = File.GetAttributes(path);
            if ((originalAttrs & FileAttributes.ReadOnly) != 0)
            {
                wasReadOnly = true;
                File.SetAttributes(path, originalAttrs & ~FileAttributes.ReadOnly);
            }
        }
        catch
        {
            // Non-fatal; continue to handle opening
        }

        try
        {
            // Open handle with Read/Write access (preferred by WofSetFileDataLocation)
            SafeFileHandle handle = CreateFile(
                path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                // Fallback to GENERIC_READ access
                handle = CreateFile(
                    path,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero);
            }

            if (handle.IsInvalid)
            {
                int err = Marshal.GetLastWin32Error();
                var status = (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION)
                    ? WofCompressionStatus.SkippedLocked
                    : (err == ERROR_ACCESS_DENIED
                        ? WofCompressionStatus.SkippedAccessDenied
                        : WofCompressionStatus.Error);

                return new WofCompressionResult(false, status, path, originalSize, originalSize, 0, err, new Win32Exception(err).Message)
                {
                    Algorithm = algorithm
                };
            }

            using (handle)
            {
                var compressionInfo = new WOF_FILE_COMPRESSION_INFO_V1
                {
                    Algorithm = algorithm,
                    Flags = 0
                };

                int structSize = Marshal.SizeOf<WOF_FILE_COMPRESSION_INFO_V1>();
                IntPtr ptr = Marshal.AllocHGlobal(structSize);
                int hr;
                try
                {
                    Marshal.StructureToPtr(compressionInfo, ptr, false);
                    hr = WofSetFileDataLocation(handle, WOF_PROVIDER_FILE, ptr, (uint)structSize);
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }

                if (hr == S_OK)
                {
                    long compressedSize = GetPhysicalFileSize(path);
                    long saved = Math.Max(0L, originalSize - compressedSize);
                    return new WofCompressionResult(true, originalSize, compressedSize, saved, S_OK)
                    {
                        Algorithm = algorithm,
                        FilePath = path
                    };
                }

                // Gracefully handle non-beneficial compression (0x80070158 / Win32 344)
                if (hr == HRESULT_COMPRESSION_NOT_BENEFICIAL || (hr & 0xFFFF) == ERROR_COMPRESSION_NOT_BENEFICIAL)
                {
                    long phys = GetPhysicalFileSize(path);
                    return new WofCompressionResult(true, originalSize, phys, 0, hr, "Compression not beneficial")
                    {
                        Algorithm = algorithm,
                        NonBeneficial = true,
                        FilePath = path
                    };
                }

                return new WofCompressionResult(false, originalSize, originalSize, 0, hr, $"WofSetFileDataLocation failed (HRESULT 0x{hr:X8})")
                {
                    Algorithm = algorithm,
                    FilePath = path
                };
            }
        }
        catch (IOException ex) when (Marshal.GetHRForException(ex) == unchecked((int)0x80070020) ||
                                     Marshal.GetHRForException(ex) == unchecked((int)0x80070021))
        {
            return new WofCompressionResult(false, WofCompressionStatus.SkippedLocked, path, originalSize, originalSize, 0, ERROR_SHARING_VIOLATION, "File is locked by another process.");
        }
        catch (UnauthorizedAccessException ex)
        {
            return new WofCompressionResult(false, WofCompressionStatus.SkippedAccessDenied, path, originalSize, originalSize, 0, ERROR_ACCESS_DENIED, ex.Message);
        }
        catch (Exception ex)
        {
            return new WofCompressionResult(false, originalSize, originalSize, 0, Marshal.GetHRForException(ex), ex.Message)
            {
                Algorithm = algorithm,
                FilePath = path
            };
        }
        finally
        {
            if (wasReadOnly)
            {
                try
                {
                    File.SetAttributes(path, originalAttrs);
                }
                catch
                {
                    // Ignore restore errors
                }
            }
        }
    }

    /// <summary>
    /// Determines whether the specified file is currently compressed via WOF or legacy NTFS compression.
    /// </summary>
    /// <param name="path">Absolute path to the target file.</param>
    /// <returns>True if compressed; otherwise false.</returns>
    public static bool IsFileCompressed(string path)
    {
        return IsFileCompressed(path, out uint _, out ulong _, out ulong _);
    }

    /// <summary>
    /// Checks whether the specified file is compressed via WOF or legacy NTFS compression,
    /// returning algorithm and size metrics.
    /// </summary>
    /// <param name="path">Absolute path to the target file.</param>
    /// <param name="algorithm">Active compression algorithm ID (0..3), or uint.MaxValue for legacy NTFS.</param>
    /// <param name="originalSize">Logical uncompressed size in bytes.</param>
    /// <param name="compressedSize">Actual physical allocated size on disk in bytes.</param>
    /// <returns>True if the file is externally backed / compressed; otherwise false.</returns>
    public static bool IsFileCompressed(
        string path,
        out uint algorithm,
        out ulong originalSize,
        out ulong compressedSize)
    {
        algorithm = 0;
        originalSize = 0;
        compressedSize = 0;

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return false;

        try
        {
            var fi = new FileInfo(path);
            originalSize = (ulong)fi.Length;
        }
        catch
        {
            return false;
        }

        long phys = GetPhysicalFileSize(path);
        compressedSize = phys >= 0 ? (ulong)phys : originalSize;

        int structSize = Marshal.SizeOf<WOF_FILE_COMPRESSION_INFO_V1>();
        IntPtr ptr = Marshal.AllocHGlobal(structSize);
        uint bufferLength = (uint)structSize;

        try
        {
            int hr = WofIsExternalFile(path, out int isExternal, out uint provider, ptr, ref bufferLength);
            if (hr == S_OK && isExternal != 0 && provider == WOF_PROVIDER_FILE)
            {
                var info = Marshal.PtrToStructure<WOF_FILE_COMPRESSION_INFO_V1>(ptr);
                algorithm = info.Algorithm;
                return true;
            }
        }
        catch
        {
            // Fall through to attribute query on probe failure
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }

        // Secondary fallback: check legacy NTFS compression attribute
        try
        {
            var attr = File.GetAttributes(path);
            if ((attr & FileAttributes.Compressed) != 0)
            {
                algorithm = uint.MaxValue; // Legacy NTFS indicator
                return true;
            }
        }
        catch
        {
            // Ignore attribute query failures
        }

        return false;
    }

    /// <summary>
    /// Convenience overload of IsFileCompressed accepting signed 64-bit integers.
    /// </summary>
    public static bool IsFileCompressed(
        string path,
        out uint algorithm,
        out long originalSize,
        out long compressedSize)
    {
        bool result = IsFileCompressed(path, out algorithm, out ulong orig, out ulong comp);
        originalSize = (long)orig;
        compressedSize = (long)comp;
        return result;
    }

    /// <summary>
    /// Decompresses a WOF-backed file, restoring it to standard physical NTFS allocation.
    /// Idempotent: returns true if the file is already decompressed or not externally backed.
    /// </summary>
    /// <param name="path">Absolute path to the target file.</param>
    /// <returns>True if the file is decompressed or was already uncompressed; otherwise false.</returns>
    public static bool DecompressFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return false;

        if (!IsFileCompressed(path))
            return true; // Already uncompressed

        bool wasReadOnly = false;
        FileAttributes originalAttrs = FileAttributes.Normal;
        try
        {
            originalAttrs = File.GetAttributes(path);
            if ((originalAttrs & FileAttributes.ReadOnly) != 0)
            {
                wasReadOnly = true;
                File.SetAttributes(path, originalAttrs & ~FileAttributes.ReadOnly);
            }
        }
        catch
        {
            // Non-fatal
        }

        try
        {
            // Open handle with GENERIC_READ (FILE_SPECIAL_ACCESS satisfies FSCTL_DELETE_EXTERNAL_BACKING
            // without triggering unintended copy-on-write during open)
            SafeFileHandle handle = CreateFile(
                path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                // Fallback to GENERIC_READ | GENERIC_WRITE (which may auto-rehydrate)
                handle = CreateFile(
                    path,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero);
            }

            if (handle.IsInvalid)
                return !IsFileCompressed(path);

            using (handle)
            {
                bool success = DeviceIoControl(
                    handle,
                    FSCTL_DELETE_EXTERNAL_BACKING,
                    IntPtr.Zero, 0,
                    IntPtr.Zero, 0,
                    out _,
                    IntPtr.Zero);

                if (!success)
                {
                    int err = Marshal.GetLastWin32Error();
                    // Error 342 (ERROR_OBJECT_NOT_EXTERNALLY_BACKED) means file is already uncompressed
                    if (err == ERROR_OBJECT_NOT_EXTERNALLY_BACKED || err == 0)
                        return true;

                    // Retry with alternative FSCTL code in case of version disparity
                    success = DeviceIoControl(
                        handle,
                        FSCTL_DELETE_EXTERNAL_BACKING_COMPAT,
                        IntPtr.Zero, 0,
                        IntPtr.Zero, 0,
                        out _,
                        IntPtr.Zero);
                }
            }

            return !IsFileCompressed(path);
        }
        catch
        {
            return !IsFileCompressed(path);
        }
        finally
        {
            if (wasReadOnly)
            {
                try
                {
                    File.SetAttributes(path, originalAttrs);
                }
                catch
                {
                    // Ignore restore errors
                }
            }
        }
    }

    /// <summary>
    /// Gets the actual physical disk size (in bytes) occupied by the file,
    /// accounting for NTFS cluster allocation, sparse files, and WOF compression.
    /// </summary>
    /// <param name="path">Absolute path to the target file.</param>
    /// <returns>Physical disk allocation in bytes, or 0 if file does not exist.</returns>
    public static long GetPhysicalFileSize(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return 0;

        uint low = GetCompressedFileSize(path, out uint high);
        if (low == 0xFFFFFFFF)
        {
            int err = Marshal.GetLastWin32Error();
            if (err != 0)
            {
                try
                {
                    var fi = new FileInfo(path);
                    return fi.Exists ? fi.Length : 0;
                }
                catch
                {
                    return 0;
                }
            }
        }

        return (long)(((ulong)high << 32) | (ulong)low);
    }
}

/// <summary>
/// Alias class matching PROJECT.md interface contract (WofNative).
/// Forwards all calls to WofCompressionNative.
/// </summary>
public static class WofNative
{
    // ─── Provider & Version Constants ───────────────────────────────────────
    public const uint WOF_PROVIDER_UNKNOWN = WofCompressionNative.WOF_PROVIDER_UNKNOWN;
    public const uint WOF_PROVIDER_WIM     = WofCompressionNative.WOF_PROVIDER_WIM;
    public const uint WOF_PROVIDER_FILE    = WofCompressionNative.WOF_PROVIDER_FILE;
    public const uint WOF_PROVIDER_CLOUD   = WofCompressionNative.WOF_PROVIDER_CLOUD;

    public const uint WOF_CURRENT_VERSION          = WofCompressionNative.WOF_CURRENT_VERSION;
    public const uint FILE_PROVIDER_CURRENT_VERSION = WofCompressionNative.FILE_PROVIDER_CURRENT_VERSION;

    // ─── CompactOS Compression Algorithms ───────────────────────────────────
    public const uint FILE_PROVIDER_COMPRESSION_XPRESS4K  = WofCompressionNative.FILE_PROVIDER_COMPRESSION_XPRESS4K;
    public const uint FILE_PROVIDER_COMPRESSION_LZX       = WofCompressionNative.FILE_PROVIDER_COMPRESSION_LZX;
    public const uint FILE_PROVIDER_COMPRESSION_XPRESS8K  = WofCompressionNative.FILE_PROVIDER_COMPRESSION_XPRESS8K;
    public const uint FILE_PROVIDER_COMPRESSION_XPRESS16K = WofCompressionNative.FILE_PROVIDER_COMPRESSION_XPRESS16K;
    public const uint FILE_PROVIDER_COMPRESSION_MAXIMUM   = WofCompressionNative.FILE_PROVIDER_COMPRESSION_MAXIMUM;

    public const uint ALGORITHM_XPRESS4K  = WofCompressionNative.ALGORITHM_XPRESS4K;
    public const uint ALGORITHM_LZX       = WofCompressionNative.ALGORITHM_LZX;
    public const uint ALGORITHM_XPRESS8K  = WofCompressionNative.ALGORITHM_XPRESS8K;
    public const uint ALGORITHM_XPRESS16K = WofCompressionNative.ALGORITHM_XPRESS16K;

    // ─── Filesystem Control Codes (FSCTL) ───────────────────────────────────
    public const uint FSCTL_SET_EXTERNAL_BACKING    = WofCompressionNative.FSCTL_SET_EXTERNAL_BACKING;
    public const uint FSCTL_GET_EXTERNAL_BACKING    = WofCompressionNative.FSCTL_GET_EXTERNAL_BACKING;
    public const uint FSCTL_DELETE_EXTERNAL_BACKING = WofCompressionNative.FSCTL_DELETE_EXTERNAL_BACKING;
    public const uint FSCTL_ENUM_EXTERNAL_BACKING   = WofCompressionNative.FSCTL_ENUM_EXTERNAL_BACKING;

    public const uint FSCTL_SET_EXTERNAL_BACKING_COMPAT    = WofCompressionNative.FSCTL_SET_EXTERNAL_BACKING_COMPAT;
    public const uint FSCTL_GET_EXTERNAL_BACKING_COMPAT    = WofCompressionNative.FSCTL_GET_EXTERNAL_BACKING_COMPAT;
    public const uint FSCTL_DELETE_EXTERNAL_BACKING_COMPAT = WofCompressionNative.FSCTL_DELETE_EXTERNAL_BACKING_COMPAT;
    public const uint FSCTL_SET_EXTERNAL_BACKING_ALT       = WofCompressionNative.FSCTL_SET_EXTERNAL_BACKING_ALT;
    public const uint FSCTL_GET_EXTERNAL_BACKING_ALT       = WofCompressionNative.FSCTL_GET_EXTERNAL_BACKING_ALT;
    public const uint FSCTL_DELETE_EXTERNAL_BACKING_ALT    = WofCompressionNative.FSCTL_DELETE_EXTERNAL_BACKING_ALT;

    // ─── Win32 & HRESULT Constants ──────────────────────────────────────────
    public const int S_OK = WofCompressionNative.S_OK;
    public const int ERROR_SUCCESS = WofCompressionNative.ERROR_SUCCESS;
    public const int ERROR_FILE_NOT_FOUND = WofCompressionNative.ERROR_FILE_NOT_FOUND;
    public const int ERROR_ACCESS_DENIED = WofCompressionNative.ERROR_ACCESS_DENIED;
    public const int ERROR_SHARING_VIOLATION = WofCompressionNative.ERROR_SHARING_VIOLATION;
    public const int ERROR_LOCK_VIOLATION = WofCompressionNative.ERROR_LOCK_VIOLATION;
    public const int ERROR_INVALID_PARAMETER = WofCompressionNative.ERROR_INVALID_PARAMETER;
    public const int ERROR_INSUFFICIENT_BUFFER = WofCompressionNative.ERROR_INSUFFICIENT_BUFFER;
    public const int ERROR_NOT_EXTERNALLY_BACKED = WofCompressionNative.ERROR_NOT_EXTERNALLY_BACKED;
    public const int ERROR_OBJECT_NOT_EXTERNALLY_BACKED = WofCompressionNative.ERROR_OBJECT_NOT_EXTERNALLY_BACKED;
    public const int ERROR_COMPRESSION_NOT_BENEFICIAL = WofCompressionNative.ERROR_COMPRESSION_NOT_BENEFICIAL;
    public const int HRESULT_COMPRESSION_NOT_BENEFICIAL = WofCompressionNative.HRESULT_COMPRESSION_NOT_BENEFICIAL;
    public const int HRESULT_OBJECT_NOT_EXTERNALLY_BACKED = WofCompressionNative.HRESULT_OBJECT_NOT_EXTERNALLY_BACKED;

    // ─── Forwarded Safe Managed Wrappers ────────────────────────────────────

    public static WofCompressionResult SetFileCompression(string path, uint algorithm = ALGORITHM_LZX) =>
        WofCompressionNative.SetFileCompression(path, algorithm);

    public static bool IsFileCompressed(string path) =>
        WofCompressionNative.IsFileCompressed(path);

    public static bool IsFileCompressed(
        string path,
        out uint algorithm,
        out ulong originalSize,
        out ulong compressedSize) =>
        WofCompressionNative.IsFileCompressed(path, out algorithm, out originalSize, out compressedSize);

    public static bool IsFileCompressed(
        string path,
        out uint algorithm,
        out long originalSize,
        out long compressedSize) =>
        WofCompressionNative.IsFileCompressed(path, out algorithm, out originalSize, out compressedSize);

    public static bool DecompressFile(string path) =>
        WofCompressionNative.DecompressFile(path);

    public static long GetPhysicalFileSize(string path) =>
        WofCompressionNative.GetPhysicalFileSize(path);
}
