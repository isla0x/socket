// Disposable localhost-only helper, built x86 and x64 by test_windows_native.py.
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
class Helper {
    [StructLayout(LayoutKind.Sequential)] struct Buf { public uint len; public IntPtr ptr; }
    [StructLayout(LayoutKind.Sequential)] struct Ov { public UIntPtr status, transferred; public uint lo, hi; public IntPtr evt; }
    [DllImport("ws2_32.dll", SetLastError=true)] static extern int send(IntPtr s, byte[] b, int n, int f);
    [DllImport("ws2_32.dll", SetLastError=true)] static extern int recv(IntPtr s, byte[] b, int n, int f);
    [DllImport("ws2_32.dll", SetLastError=true)] static extern int WSASend(IntPtr s, Buf[] b, uint n, out uint bytes, uint f, IntPtr ov, IntPtr cb);
    [DllImport("ws2_32.dll", SetLastError=true)] static extern int WSARecv(IntPtr s, Buf[] b, uint n, out uint bytes, ref uint f, IntPtr ov, IntPtr cb);
    [DllImport("ws2_32.dll", SetLastError=true)] static extern bool WSAGetOverlappedResult(IntPtr s, IntPtr ov, out uint bytes, bool wait, out uint flags);
    [DllImport("kernel32.dll")] static extern IntPtr CreateEvent(IntPtr attr, bool manual, bool initial, string name);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateIoCompletionPort(IntPtr file, IntPtr port, UIntPtr key, uint threads);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetQueuedCompletionStatus(IntPtr port, out uint count, out UIntPtr key, out IntPtr ov, uint timeout);
    static void Check(bool condition) { if (!condition) throw new Exception("Test failed: " + Marshal.GetLastWin32Error()); }
    static Socket Connect(int port) { var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp); s.Connect(IPAddress.Loopback,port); return s; }
    static void Main(string[] args) {
        int port = int.Parse(args[0]); string arch = IntPtr.Size == 4 ? "x86" : "x64";
        Console.WriteLine("READY " + arch); Console.ReadLine();
        using(var s=Connect(port)) {
            byte[] tx=Encoding.ASCII.GetBytes("SYNC-"+arch), rx=new byte[128];
            Check(send(s.Handle,tx,tx.Length,0)==tx.Length);
            int n=recv(s.Handle,rx,rx.Length,0); Check(Encoding.ASCII.GetString(rx,0,n)=="ECHO:SYNC-"+arch);
        }
        IntPtr a=Marshal.AllocHGlobal(128), b=Marshal.AllocHGlobal(128);
        try {
            using(var s=Connect(port)) {
                byte[] tx=Encoding.ASCII.GetBytes("GATHER-"+arch); Marshal.Copy(tx,0,a,tx.Length);
                uint n,f=0; var bufs=new Buf[]{new Buf{len=7,ptr=a},new Buf{len=(uint)(tx.Length-7),ptr=IntPtr.Add(a,7)}};
                Check(WSASend(s.Handle,bufs,2,out n,0,IntPtr.Zero,IntPtr.Zero)==0 && n==tx.Length);
                var rx=new Buf[]{new Buf{len=5,ptr=a},new Buf{len=123,ptr=b}};
                Check(WSARecv(s.Handle,rx,2,out n,ref f,IntPtr.Zero,IntPtr.Zero)==0);
                byte[] got=new byte[n]; Marshal.Copy(a,got,0,5); Marshal.Copy(b,got,5,(int)n-5);
                Check(Encoding.ASCII.GetString(got)=="ECHO:GATHER-"+arch);
            }
            foreach(bool iocp in new bool[]{false,true}) using(var s=Connect(port)) {
                byte[] tx=Encoding.ASCII.GetBytes((iocp?"IOCP-":"OVERLAPPED-")+arch);
                IntPtr evt=CreateEvent(IntPtr.Zero,true,false,null), ovp=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Ov))), portHandle=IntPtr.Zero;
                try {
                    Marshal.StructureToPtr(new Ov{evt=iocp?IntPtr.Zero:evt},ovp,false);
                    if(iocp) { portHandle=CreateIoCompletionPort(s.Handle,IntPtr.Zero,UIntPtr.Zero,0); Check(portHandle!=IntPtr.Zero); }
                    uint n,f=0;var rx=new Buf[]{new Buf{len=128,ptr=a}};
                    int r=WSARecv(s.Handle,rx,1,out n,ref f,ovp,IntPtr.Zero);
                    Check(r==-1 && Marshal.GetLastWin32Error()==997);
                    Check(send(s.Handle,tx,tx.Length,0)==tx.Length);
                    if(iocp) { UIntPtr key;IntPtr done;Check(GetQueuedCompletionStatus(portHandle,out n,out key,out done,5000) && done==ovp); }
                    else Check(WSAGetOverlappedResult(s.Handle,ovp,out n,true,out f));
                    byte[] got=new byte[n];Marshal.Copy(a,got,0,(int)n);Check(Encoding.ASCII.GetString(got)=="ECHO:"+Encoding.ASCII.GetString(tx));
                } finally { if(portHandle!=IntPtr.Zero)CloseHandle(portHandle);CloseHandle(evt);Marshal.FreeHGlobal(ovp); }
            }
        } finally { Marshal.FreeHGlobal(a);Marshal.FreeHGlobal(b); }
        Console.WriteLine("PASS " + arch);
    }
}
