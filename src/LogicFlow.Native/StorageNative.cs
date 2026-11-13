// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Native — Storage & Volume Interop Layer
// Proprietary implementation by DelgadoLogic.Tech
// Win32 bindings for ReFS Block Cloning, NTFS Hard Links, and Volume GUIDs
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace LogicFlow.Native;

/// <summary>
/// Native Win32 storage management primitives for canonical volume resolution,
/// ReFS block cloning, NTFS hard link consolidation, and atomic file swaps.
/// </summary>
public static class StorageNative
{
    #region Win32 Constants & Control Codes

    // FSCTL Control Codes
    public const uint FSCTL_DUPLICATE_EXTENTS_TO_FILE = 0x00098344;

    // File System Feature Flags
    public const uint FILE_CASE_SENSITIVE_SEARCH       = 0x00000001;
    public const uint FILE_CASE_PRESERVED_NAMES        = 0x00000002;
    public const uint FILE_UNICODE_ON_DISK             = 0x00000004;
    public const uint FILE_PERSISTENT_ACLS             = 0x00000008;
    public const uint FILE_FILE_COMPRESSION            = 0x00000010;
    public const uint FILE_VOLUME_QUOTAS               = 0x00000020;
    public const uint FILE_SUPPORTS_SPARSE_FILES       = 0x00000040;
    public const uint FILE_SUPPORTS_REPARSE_POINTS     = 0x00000080;
    public const uint FILE_SUPPORTS_BLOCK_REFCOUNTING  = 0x08000000; // ReFS CoW Block Cloning support

    // GetFinalPathNameByHandle Flags
    public const uint VOLUME_NAME_DOS        = 0x0;
    public const uint VOLUME_NAME_GUID       = 0x1;
    public const uint VOLUME_NAME_NT         = 0x2;
    public const uint VOLUME_NAME_NONE       = 0x4;
    public const uint FILE_NAME_NORMALIZED   = 0x0;
    public const uint FILE_NAME_OPENED       = 0x8;

    // MoveFileEx Flags
    public const uint MOVEFILE_REPLACE_EXISTING   = 0x00000001;
    public const uint MOVEFILE_COPY_ALLOWED        = 0x00000002;
    public const uint MOVEFILE_DELAY_UNTIL_REBOOT  = 0x00000004;
    public const uint MOVEFILE_WRITE_THROUGH       = 0x00000008;

    // File Access Rights
    public const uint GENERIC_READ           = 0x80000000;
    public const uint GENERIC_WRITE          = 0x40000000;
    public const uint FILE_READ_ATTRIBUTES   = 0x0080;
    public const uint FILE_WRITE_DATA        = 0x0002;

    // File Share Modes
    public const uint FILE_SHARE_READ        = 0x00000001;
    public const uint FILE_SHARE_WRITE       = 0x00000002;
    public const uint FILE_SHARE_DELETE      = 0x00000004;

    // File Creation Dispositions
    public const uint CREATE_NEW             = 1;
    public const uint CREATE_ALWAYS          = 2;
    public const uint OPEN_EXISTING          = 3;
    public const uint OPEN_ALWAYS            = 4;
    public const uint TRUNCATE_EXISTING      = 5;

    // File Flags & Attributes
    public const uint FILE_ATTRIBUTE_NORMAL         = 0x00000080;
    public const uint FILE_FLAG_BACKUP_SEMANTICS    = 0x02000000;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT  = 0x00200000;

    // SetFilePointer Move Methods
    public const uint FILE_BEGIN    = 0;
    public const uint FILE_CURRENT  = 1;
    public const uint FILE_END      = 2;

    // Common Win32 Error Codes
    public const int ERROR_SUCCESS               = 0;
    public const int ERROR_INVALID_FUNCTION      = 1;
    public const int ERROR_NOT_SAME_DEVICE       = 17;
    public const int ERROR_SHARING_VIOLATION     = 32;
    public const int ERROR_NOT_SUPPORTED         = 50;
    public const int ERROR_INVALID_PARAMETER     = 87;
    public const int ERROR_ALREADY_EXISTS        = 183;
    public const int ERROR_MORE_DATA             = 234;
    public const int ERROR_FILE_SYSTEM_LIMITATION = 665;
    public const int ERROR_BLOCK_TOO_MANY_REFERENCES = 347;

    #endregion

    #region Data Structures

    /// <summary>
    /// Input buffer for FSCTL_DUPLICATE_EXTENTS_TO_FILE.
    /// All offsets and byte count must be cluster-aligned on the volume.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct DUPLICATE_EXTENTS_DATA
    {
        public IntPtr FileHandle;      // Handle to source file (GENERIC_READ)
        public long SourceFileOffset; // Source offset in bytes (must be cluster-aligned)
        public long TargetFileOffset; // Target offset in bytes (must be cluster-aligned)
        public long ByteCount;        // Extent length in bytes (must be cluster-aligned)
    }

    /// <summary>
    /// Standard Win32 file information returned by GetFileInformationByHandle.
    /// Used for querying file index (MFT record identifier) and link count.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct BY_HANDLE_FILE_INFORMATION
    {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint dwVolumeSerialNumber;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint nNumberOfLinks;
        public uint nFileIndexHigh;
        public uint nFileIndexLow;

        public readonly ulong FileSize => ((ulong)nFileSizeHigh << 32) | nFileSizeLow;
        public readonly ulong FileIndex => ((ulong)nFileIndexHigh << 32) | nFileIndexLow;
    }

    /// <summary>
    /// High-level description of volume filesystem capabilities, cluster size, and cloning support.
    /// </summary>
    public sealed record VolumeInformation(
        string RootPath,
        string VolumeName,
        uint VolumeSerialNumber,
        uint MaximumComponentLength,
        uint FileSystemFlags,
        string FileSystemName,
        uint SectorsPerCluster,
        uint BytesPerSector,
        uint ClusterSize,
        bool SupportsBlockCloning,
        bool SupportsReparsePoints
    );

    #endregion

    #region P/Invoke Declarations

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetFinalPathNameByHandleW")]
    public static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile,
        [Out] StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetVolumeInformationW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetVolumeInformationW(
        string lpRootPathName,
        [Out] StringBuilder? lpVolumeNameBuffer,
        uint nVolumeNameSize,
        out uint lpVolumeSerialNumber,
        out uint lpMaximumComponentLength,
        out uint lpFileSystemFlags,
        [Out] StringBuilder? lpFileSystemNameBuffer,
        uint nFileSystemNameSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetDiskFreeSpaceW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpaceW(
        string lpRootPathName,
        out uint lpSectorsPerCluster,
        out uint lpBytesPerSector,
        out uint lpNumberOfFreeClusters,
        out uint lpTotalNumberOfClusters);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateHardLinkW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateHardLinkW(
        string lpFileName,
        string lpExistingFileName,
        IntPtr lpSecurityAttributes);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "MoveFileExW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool MoveFileExW(
        string lpExistingFileName,
        string lpNewFileName,
        uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        ref DUPLICATE_EXTENTS_DATA lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetEndOfFile(SafeFileHandle hFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "DeleteFileW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteFileW(string lpFileName);

    #endregion

    #region Safe Managed Wrappers

    /// <summary>
    /// Opens a file or directory handle with backup semantics, allowing handle acquisition
    /// on directories, junctions, symlinks, and files without exclusive locking.
    /// </summary>
    public static SafeFileHandle OpenHandle(
        string path,
        uint desiredAccess = 0,
        uint shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        uint creationDisposition = OPEN_EXISTING,
        uint flagsAndAttributes = FILE_FLAG_BACKUP_SEMANTICS)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var handle = CreateFileW(
            path,
            desiredAccess,
            shareMode,
            IntPtr.Zero,
            creationDisposition,
            flagsAndAttributes,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"Failed to open handle for '{path}' (Win32 Error: {err}).");
        }

        return handle;
    }

    /// <summary>
    /// Attempts to open a file or directory handle safely without throwing.
    /// </summary>
    public static bool TryOpenHandle(
        string path,
        out SafeFileHandle handle,
        uint desiredAccess = 0,
        uint shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        uint creationDisposition = OPEN_EXISTING,
        uint flagsAndAttributes = FILE_FLAG_BACKUP_SEMANTICS)
    {
        handle = CreateFileW(
            path,
            desiredAccess,
            shareMode,
            IntPtr.Zero,
            creationDisposition,
            flagsAndAttributes,
            IntPtr.Zero);

        return !handle.IsInvalid;
    }

    /// <summary>
    /// Retrieves the canonical path name for a file or directory handle.
    /// By default resolves to the volume GUID path format: \\?\Volume{guid}\relative\path.
    /// </summary>
    public static string GetFinalPathName(
        SafeFileHandle handle,
        uint flags = VOLUME_NAME_GUID | FILE_NAME_NORMALIZED)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid)
        {
            throw new ArgumentException("Handle is invalid.", nameof(handle));
        }

        var sb = new StringBuilder(512);
        uint result = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, flags);

        if (result == 0)
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"GetFinalPathNameByHandle failed (Win32 Error: {err}).");
        }

        if (result > sb.Capacity)
        {
            sb.EnsureCapacity((int)result + 1);
            result = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, flags);
            if (result == 0)
            {
                int err = Marshal.GetLastWin32Error();
                throw new Win32Exception(err, $"GetFinalPathNameByHandle failed on second pass (Win32 Error: {err}).");
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Retrieves the canonical path for any existing path or junction, automatically opening
    /// the handle with backup semantics and resolving to volume GUID format.
    /// </summary>
    public static string GetFinalPathName(
        string path,
        uint flags = VOLUME_NAME_GUID | FILE_NAME_NORMALIZED)
    {
        using var handle = OpenHandle(path, desiredAccess: 0);
        return GetFinalPathName(handle, flags);
    }

    /// <summary>
    /// Safely attempts to resolve the canonical path name without throwing.
    /// </summary>
    public static bool TryGetFinalPathName(
        string path,
        out string? finalPath,
        uint flags = VOLUME_NAME_GUID | FILE_NAME_NORMALIZED)
    {
        finalPath = null;
        if (!TryOpenHandle(path, out var handle, desiredAccess: 0))
        {
            return false;
        }

        using (handle)
        {
            var sb = new StringBuilder(512);
            uint result = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, flags);

            if (result == 0)
            {
                return false;
            }

            if (result > sb.Capacity)
            {
                sb.EnsureCapacity((int)result + 1);
                result = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, flags);
                if (result == 0)
                {
                    return false;
                }
            }

            finalPath = sb.ToString();
            return true;
        }
    }

    /// <summary>
    /// Queries file system information, feature flags (including ReFS block cloning),
    /// and cluster geometry for a root volume path (e.g. "C:\", "D:\", or "\\?\Volume{guid}\").
    /// </summary>
    public static VolumeInformation GetVolumeInformation(string rootPathName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPathName);

        string root = rootPathName;
        if (!root.EndsWith('\\'))
        {
            root += "\\";
        }

        var volName = new StringBuilder(260);
        var fsName = new StringBuilder(260);

        if (!GetVolumeInformationW(
            root,
            volName,
            (uint)volName.Capacity,
            out uint serial,
            out uint maxCompLen,
            out uint fsFlags,
            fsName,
            (uint)fsName.Capacity))
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"GetVolumeInformation failed for '{root}' (Win32 Error: {err}).");
        }

        uint clusterSize = 4096;
        uint sectorsPerCluster = 8;
        uint bytesPerSector = 512;

        if (GetDiskFreeSpaceW(root, out uint spc, out uint bps, out _, out _))
        {
            sectorsPerCluster = spc;
            bytesPerSector = bps;
            clusterSize = spc * bps;
        }

        bool supportsBlockCloning = (fsFlags & FILE_SUPPORTS_BLOCK_REFCOUNTING) != 0;
        bool supportsReparsePoints = (fsFlags & FILE_SUPPORTS_REPARSE_POINTS) != 0;

        return new VolumeInformation(
            RootPath: root,
            VolumeName: volName.ToString(),
            VolumeSerialNumber: serial,
            MaximumComponentLength: maxCompLen,
            FileSystemFlags: fsFlags,
            FileSystemName: fsName.ToString(),
            SectorsPerCluster: sectorsPerCluster,
            BytesPerSector: bytesPerSector,
            ClusterSize: clusterSize > 0 ? clusterSize : 4096,
            SupportsBlockCloning: supportsBlockCloning,
            SupportsReparsePoints: supportsReparsePoints
        );
    }

    /// <summary>
    /// Safely attempts to query volume information without throwing.
    /// </summary>
    public static bool TryGetVolumeInformation(string rootPathName, out VolumeInformation? info)
    {
        info = null;
        try
        {
            info = GetVolumeInformation(rootPathName);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Creates a native NTFS hard link pointing from newFileName to existingFileName.
    /// </summary>
    public static void CreateHardLink(string newFileName, string existingFileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newFileName);
        ArgumentException.ThrowIfNullOrWhiteSpace(existingFileName);

        if (!CreateHardLinkW(newFileName, existingFileName, IntPtr.Zero))
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"CreateHardLink failed: '{newFileName}' -> '{existingFileName}' (Win32 Error: {err}).");
        }
    }

    /// <summary>
    /// Safely attempts to create an NTFS hard link, returning success or failure with Win32 error code.
    /// </summary>
    public static bool TryCreateHardLink(string newFileName, string existingFileName, out int errorCode)
    {
        errorCode = 0;
        if (!CreateHardLinkW(newFileName, existingFileName, IntPtr.Zero))
        {
            errorCode = Marshal.GetLastWin32Error();
            return false;
        }
        return true;
    }

    /// <summary>
    /// Atomically replaces or moves existingFileName to newFileName using MoveFileExW.
    /// </summary>
    public static void MoveFileEx(
        string existingFileName,
        string newFileName,
        uint flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(existingFileName);
        ArgumentException.ThrowIfNullOrWhiteSpace(newFileName);

        if (!MoveFileExW(existingFileName, newFileName, flags))
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"MoveFileEx failed: '{existingFileName}' -> '{newFileName}' (Win32 Error: {err}).");
        }
    }

    /// <summary>
    /// Safely attempts to execute MoveFileEx, returning success or failure with Win32 error code.
    /// </summary>
    public static bool TryMoveFileEx(
        string existingFileName,
        string newFileName,
        uint flags,
        out int errorCode)
    {
        errorCode = 0;
        if (!MoveFileExW(existingFileName, newFileName, flags))
        {
            errorCode = Marshal.GetLastWin32Error();
            return false;
        }
        return true;
    }

    /// <summary>
    /// Clones extents from sourceHandle into targetHandle on ReFS via FSCTL_DUPLICATE_EXTENTS_TO_FILE.
    /// Offsets and byte count must be cluster-aligned.
    /// </summary>
    public static void DuplicateExtents(
        SafeFileHandle sourceHandle,
        SafeFileHandle targetHandle,
        long sourceOffset,
        long targetOffset,
        long byteCount)
    {
        ArgumentNullException.ThrowIfNull(sourceHandle);
        ArgumentNullException.ThrowIfNull(targetHandle);

        var data = new DUPLICATE_EXTENTS_DATA
        {
            FileHandle = sourceHandle.DangerousGetHandle(),
            SourceFileOffset = sourceOffset,
            TargetFileOffset = targetOffset,
            ByteCount = byteCount
        };

        if (!DeviceIoControl(
            targetHandle,
            FSCTL_DUPLICATE_EXTENTS_TO_FILE,
            ref data,
            (uint)Marshal.SizeOf<DUPLICATE_EXTENTS_DATA>(),
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero))
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"DeviceIoControl FSCTL_DUPLICATE_EXTENTS_TO_FILE failed (Win32 Error: {err}).");
        }
    }

    /// <summary>
    /// Safely attempts to clone extents via FSCTL_DUPLICATE_EXTENTS_TO_FILE without throwing.
    /// </summary>
    public static bool TryDuplicateExtents(
        SafeFileHandle sourceHandle,
        SafeFileHandle targetHandle,
        long sourceOffset,
        long targetOffset,
        long byteCount,
        out int errorCode)
    {
        errorCode = 0;
        var data = new DUPLICATE_EXTENTS_DATA
        {
            FileHandle = sourceHandle.DangerousGetHandle(),
            SourceFileOffset = sourceOffset,
            TargetFileOffset = targetOffset,
            ByteCount = byteCount
        };

        if (!DeviceIoControl(
            targetHandle,
            FSCTL_DUPLICATE_EXTENTS_TO_FILE,
            ref data,
            (uint)Marshal.SizeOf<DUPLICATE_EXTENTS_DATA>(),
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero))
        {
            errorCode = Marshal.GetLastWin32Error();
            return false;
        }
        return true;
    }

    /// <summary>
    /// Retrieves file information (MFT index, link count, volume serial) by handle.
    /// </summary>
    public static BY_HANDLE_FILE_INFORMATION GetFileInformation(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);

        if (!GetFileInformationByHandle(handle, out var info))
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"GetFileInformationByHandle failed (Win32 Error: {err}).");
        }
        return info;
    }

    /// <summary>
    /// Retrieves file information by path using backup semantics.
    /// </summary>
    public static BY_HANDLE_FILE_INFORMATION GetFileInformation(string path)
    {
        using var handle = OpenHandle(path, desiredAccess: 0);
        return GetFileInformation(handle);
    }

    /// <summary>
    /// Returns the exact number of NTFS hard links pointing to the given file.
    /// </summary>
    public static uint GetHardLinkCount(string path)
    {
        return GetFileInformation(path).nNumberOfLinks;
    }

    /// <summary>
    /// Pre-allocates or resizes a file to the specified logical length using SetFilePointerEx and SetEndOfFile.
    /// Required before executing FSCTL_DUPLICATE_EXTENTS_TO_FILE on ReFS.
    /// </summary>
    public static void SetFileLength(SafeFileHandle handle, long length)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Length cannot be negative.");
        }

        if (!SetFilePointerEx(handle, length, out _, FILE_BEGIN))
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"SetFilePointerEx to {length} failed (Win32 Error: {err}).");
        }

        if (!SetEndOfFile(handle))
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"SetEndOfFile to {length} failed (Win32 Error: {err}).");
        }
    }

    #endregion
}
