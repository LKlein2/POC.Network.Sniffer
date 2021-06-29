using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace POC.Network.Sniffer.Models.Flags
{
    public class IPFlagModel
    {
        public string ReservedBit { get; set; }
        public string DontFragment { get; set; }
        public string MoreFragments { get; set; }

        public IPFlagModel(ushort flags)
        {
            byte[] vOut = BitConverter.GetBytes(flags);

            foreach (var Onebyte in vOut)
            {
                var flagByte = Convert.ToString(Onebyte, 2).PadLeft(8, '0');

                ReservedBit   = $"{flagByte.Substring(0, 1)}... .... Reserved bit: {(flagByte.Substring(0, 1) == "1" ? "Set" : "Not Set")}";
                DontFragment  = $".{flagByte.Substring(1, 1)}.. .... Don't fragment: {(flagByte.Substring(1, 1) == "1" ? "Set" : "Not Set")}";
                MoreFragments = $"..{flagByte.Substring(2, 1)}. .... More Fragments: {(flagByte.Substring(2, 1) == "1" ? "Set" : "Not Set")}";

            }
        }
    }
}
