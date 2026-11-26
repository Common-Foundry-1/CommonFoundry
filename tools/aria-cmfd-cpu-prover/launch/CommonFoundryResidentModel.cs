using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.ComponentModel;
public sealed unsafe class CommonFoundryResidentModel : IDisposable {
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessWorkingSetSize(IntPtr process, out UIntPtr min, out UIntPtr max);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetProcessWorkingSetSize(IntPtr process, UIntPtr min, UIntPtr max);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualLock(IntPtr address, UIntPtr bytes);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualUnlock(IntPtr address, UIntPtr bytes);
    readonly MemoryMappedFile file;
    readonly MemoryMappedViewAccessor view;
    readonly UIntPtr bytes;
    UIntPtr oldMin, oldMax;
    bool resized, pointerAcquired;
    byte* data;
    public long Length { get; }
    public bool Locked { get; private set; }
    public string LockError { get; private set; }
    public CommonFoundryResidentModel(string path) {
        Length = new FileInfo(path).Length;
        bytes = new UIntPtr((ulong)Length);
        file = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        view = file.CreateViewAccessor(0, Length, MemoryMappedFileAccess.Read);
        try {
            view.SafeMemoryMappedViewHandle.AcquirePointer(ref data);
            pointerAcquired = true;
            ulong minimum = (ulong)Length + (256UL << 20);
            ulong maximum = minimum + (512UL << 20);
            var proc = GetCurrentProcess();
            resized = GetProcessWorkingSetSize(proc, out oldMin, out oldMax) &&
                      SetProcessWorkingSetSize(proc, new UIntPtr(minimum), new UIntPtr(maximum));
            Locked = resized && VirtualLock((IntPtr)data, bytes);
            if (!Locked) LockError = new Win32Exception(Marshal.GetLastWin32Error()).Message;
            Touch();
        } catch {
            Dispose();
            throw;
        }
    }
    public long Touch() {
        long total = 0;
        for (long offset = 0; offset < Length; offset += Environment.SystemPageSize)
            total += data[offset];
        return total;
    }
    public void Dispose() {
        if (Locked) VirtualUnlock((IntPtr)data, bytes);
        if (pointerAcquired) view.SafeMemoryMappedViewHandle.ReleasePointer();
        view.Dispose();
        file.Dispose();
        if (resized) SetProcessWorkingSetSize(GetCurrentProcess(), oldMin, oldMax);
    }
}
