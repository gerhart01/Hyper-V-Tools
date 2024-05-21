using System;
using System.IO;
using static PTViewClient.PTView.Native;
using static PTViewClient.PTView.Driver.Internal.Constants;
using PTViewClient.PTView.Hvlibdotnet;
using System.Linq;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace PTViewClient.PTView.Driver
{
    public unsafe class DriverInterface
    {
        public IntPtr DriverHandle;

        public bool Initialize(string symlink)
        {
            return true;
        }

        private byte[] Get4Bytes(ulong parm1)
        {
            byte[] retVal = new byte[4];

            retVal[0] = (byte)((parm1 >> 24) & 0xFF);
            retVal[1] = (byte)((parm1 >> 16) & 0xFF);
            retVal[2] = (byte)((parm1 >> 8) & 0xFF);
            retVal[3] = (byte)(parm1 & 0xFF);

            return retVal;
        }

        private byte[] Get8Bytes(ulong parm1, ulong parm2)
        {
            byte[] retVal = new byte[8];

            Array.Copy(Get4Bytes(parm1), 0, retVal, 0, 4);
            Array.Copy(Get4Bytes(parm2), 0, retVal, 4, 4);

            return retVal;
        }
        public PTE[] DumpPageTables(ulong pfn)
        {
            ulong[] ptBuffer = new ulong[512];

            pfn = pfn << 12;

            bool bResult = Hvlib.ReadPhysicalMemory(Hvlib.VmHandle, pfn, (ulong) ptBuffer.Length * sizeof(ulong), ptBuffer);

            PTE[] Pte = ptBuffer.Select(x => (PTE)x).ToArray();

            return Pte;
        }

        public byte[] DumpPage(ulong pfn, bool largePage)
        {
            uint bufferLength = largePage ? 0x1000 * 512u : 0x1000;
            byte[] pageBuffer = new byte[bufferLength];

            pfn = pfn << 12;

            bool bResult = Hvlib.ReadPhysicalMemory(Hvlib.VmHandle, pfn, bufferLength, pageBuffer);

            return pageBuffer;
        }

        public void Close()
        {
            CloseHandle(DriverHandle);
        }
    }
}
