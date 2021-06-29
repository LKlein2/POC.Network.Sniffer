using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace POC.Network.Sniffer.Models
{
    public class WifiHeader
    {
        public ushort _frameControl;
        public ushort _duration;
        public byte[] _address1;
        public byte[] _address2;
        public byte[] _address3;
        public ushort _sequenceControl;
        public byte[] _address4;
        public byte[] _frameBody;
        public uint? _fcs;

        public string _version;

        public WifiHeader(byte[] byBuffer)
        {
            _frameControl = GetFrameControl(byBuffer);
            _duration = GetDuration(byBuffer);
            _address1 = GetAddress(byBuffer, 4);
            _address2 = GetAddress(byBuffer, 10);
            _address3 = GetAddress(byBuffer, 16);
            _sequenceControl = GetSequenceControl(byBuffer);
            _address4 = GetAddress(byBuffer, 24);
            _frameBody = GetFrameBody(byBuffer);
            _fcs = GetFcs(byBuffer);
            _version = GetVersion();
        }

        private static ushort GetFrameControl(byte[] s)
        {
            var networkByte = BitConverter.ToInt16(s, 0);
            return (ushort)networkByte;
        }

        private static ushort GetDuration(byte[] s)
        {
            var networkByte = BitConverter.ToInt16(s, 2);
            return (ushort)networkByte;
        }

        private static byte[] GetAddress(byte[] s, int offset)
        {
            if (s.Length < offset + 6) return null;
            var address = new byte[6];
            Array.Copy(s, offset, address, 0, 6);
            return address;
        }

        private static ushort GetSequenceControl(byte[] s)
        {
            var networkByte = BitConverter.ToInt16(s, 22);
            return (ushort)networkByte;
        }

        private static byte[] GetFrameBody(byte[] s)
        {
            if (s.Length <= 34) return null;

            var frameBoby = new byte[s.Length - 34];
            Array.Copy(s, 30, frameBoby, 0, s.Length - 34);
            return frameBoby;
        }

        private static uint? GetFcs(byte[] s)
        {
            if (s.Length < 34) return null;

            var networkByte = BitConverter.ToUInt32(s, s.Length - 4);
            return networkByte;
        }

        public string GetVersion()
        {
            var version = _frameControl & 0x0003;
            return version.ToString();
        }
    }
}
