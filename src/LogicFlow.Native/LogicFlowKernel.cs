// LogicFlow.Native — Kernel-Level Interop Layer
// Proprietary implementation by DelgadoLogic.Tech
// P/Invoke declarations for raw disk I/O, CNG crypto, and driver management

using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;

namespace LogicFlow.Native;

/// <summary>
/// Low-level disk I/O operations via Win32 CreateFile + ReadFile for raw sector access.
/// Used by LogicFlow.Lazarus for data recovery and LogicFlow.Native for S.M.A.R.T.
/// </summary>
public static class DiskIO
{
    // ─── File Access Constants ──────────────────────────────────
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_NO_BUFFERING = 0x20000000;
    public const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;

    // ─── IOCTL Constants ────────────────────────────────────────
    public const uint IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000;
    public const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
    public const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080;
    public const uint IOCTL_DISK_GET_PARTITION_INFO_EX = 0x00070048;
    public const uint IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x00070050;
    public const uint IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000;

    // ─── SMART Constants ────────────────────────────────────────
    public const uint SMART_GET_VERSION = 0x00074080;
    public const uint SMART_RCV_DRIVE_DATA = 0x0007C088;
    public const uint SMART_SEND_DRIVE_COMMAND = 0x0007C084;
    public const byte SMART_CMD_ENABLE_OPERATIONS = 0xD8;
    public const byte SMART_CMD_RETURN_STATUS = 0xDA;
    public const byte ID_CMD = 0xEC;
    public const byte SMART_CMD_READ_ATTRIBUTES = 0xD0;
    public const byte SMART_CMD_READ_THRESHOLDS = 0xD1;

    // ─── Win32 Imports ──────────────────────────────────────────
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadFile(
        SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteFile(
        SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        ref SENDCMDINPARAMS lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointerEx(
        SafeFileHandle hFile, long liDistanceToMove,
        out long lpNewFilePointer, uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FlushFileBuffers(SafeFileHandle hFile);

    /// <summary>
    /// Opens a physical drive for raw sector-level read access.
    /// Requires Administrator privileges.
    /// </summary>
    public static SafeFileHandle OpenPhysicalDrive(int driveNumber, bool writeAccess = false)
    {
        var access = GENERIC_READ | (writeAccess ? GENERIC_WRITE : 0);
        var handle = CreateFile(
            $"\\\\.\\PhysicalDrive{driveNumber}",
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            IntPtr.Zero);

        if (handle.IsInvalid)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                $"Failed to open PhysicalDrive{driveNumber}. Run as Administrator.");

        return handle;
    }

    /// <summary>
    /// Reads raw sectors from disk. Buffer must be sector-aligned (512-byte multiple).
    /// </summary>
    public static byte[] ReadSectors(SafeFileHandle handle, long offset, int sectorCount, int sectorSize = 512)
    {
        var buffer = new byte[sectorCount * sectorSize];
        SetFilePointerEx(handle, offset, out _, 0);
        ReadFile(handle, buffer, (uint)buffer.Length, out var bytesRead, IntPtr.Zero);
        if (bytesRead != buffer.Length)
            Array.Resize(ref buffer, (int)bytesRead);
        return buffer;
    }
}

/// <summary>
/// CNG (Cryptography Next Generation) interop for hardware-accelerated crypto.
/// Used by OmniLicense for RSA validation and LogicFlow.Lazarus for file hashing.
/// </summary>
public static class CryptoNative
{
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptOpenAlgorithmProvider(
        out IntPtr phAlgorithm, string pszAlgId, string? pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptGenerateSymmetricKey(
        IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, uint cbKeyObject,
        byte[] pbSecret, uint cbSecret, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptEncrypt(
        IntPtr hKey, byte[] pbInput, uint cbInput, IntPtr pPaddingInfo,
        byte[]? pbIV, uint cbIV, byte[]? pbOutput, uint cbOutput,
        out uint pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptDecrypt(
        IntPtr hKey, byte[] pbInput, uint cbInput, IntPtr pPaddingInfo,
        byte[]? pbIV, uint cbIV, byte[]? pbOutput, uint cbOutput,
        out uint pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptDestroyKey(IntPtr hKey);

    // Algorithm identifiers
    public const string BCRYPT_AES_ALGORITHM = "AES";
    public const string BCRYPT_RSA_ALGORITHM = "RSA";
    public const string BCRYPT_SHA256_ALGORITHM = "SHA256";
    public const string BCRYPT_SHA512_ALGORITHM = "SHA512";

    // Flags
    public const uint BCRYPT_BLOCK_PADDING = 0x00000001;
}

/// <summary>
/// Windows Filtering Platform (WFP) interop stubs for network monitoring.
/// LogicFlow.NetFilter.sys driver interface.
/// </summary>
public static class NetFilterNative
{
    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmEngineOpen0(
        string? serverName, uint authnService, IntPtr authIdentity,
        IntPtr session, out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmFilterAdd0(
        IntPtr engineHandle, IntPtr filter, IntPtr sd, out ulong id);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);
}

/// <summary>
/// Minifilter driver management stubs for disk I/O monitoring.
/// LogicFlow.DiskMonitor.sys interface.
/// </summary>
public static class MinifilterNative
{
    [DllImport("fltlib.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int FilterLoad(string lpFilterName);

    [DllImport("fltlib.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int FilterUnload(string lpFilterName);

    [DllImport("fltlib.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, IntPtr lpContext, uint dwSizeOfContext,
        IntPtr lpSecurityAttributes, out SafeFileHandle hPort);

    [DllImport("fltlib.dll", SetLastError = true)]
    public static extern int FilterSendMessage(
        SafeFileHandle hPort, IntPtr lpInBuffer, uint dwInBufferSize,
        IntPtr lpOutBuffer, uint dwOutBufferSize, out uint lpBytesReturned);

    public const string LOGICFLOW_DISK_MONITOR_PORT = "\\LogicFlowDiskMonitor";
    public const string LOGICFLOW_DISK_MONITOR_DRIVER = "LogicFlowDiskMon";
}

// ─── SMART Structures ──────────────────────────────────────────
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct SENDCMDINPARAMS
{
    public uint cBufferSize;
    public IDEREGS irDriveRegs;
    public byte bDriveNumber;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
    public byte[] bReserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public uint[] dwReserved;
    public byte bBuffer;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IDEREGS
{
    public byte bFeaturesReg;
    public byte bSectorCountReg;
    public byte bSectorNumberReg;
    public byte bCylLowReg;
    public byte bCylHighReg;
    public byte bDriveHeadReg;
    public byte bCommandReg;
    public byte bReserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct SENDCMDOUTPARAMS
{
    public uint cBufferSize;
    public DRIVERSTATUS DriverStatus;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
    public byte[] bBuffer;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DRIVERSTATUS
{
    public byte bDriverError;
    public byte bIDEStatus;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public byte[] bReserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public uint[] dwReserved;
}
