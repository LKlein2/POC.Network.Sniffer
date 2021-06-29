using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace POC.Network.Sniffer.Models.Flags
{
    public class TCPFlagModel
    {
        public string Reserved { get; set; }
        public string Nonce { get; set; }
        public string Congestion { get; set; }
        public string ECNEcho { get; set; }
        public string Urgent { get; set; }
        public string Acknowledgment{ get; set; }
        public string Push { get; set; }
        public string Reset { get; set; }
        public string Syn { get; set; }
        public string Fin { get; set; }

        public TCPFlagModel(ushort flags)
        {

            byte[] vOut = BitConverter.GetBytes(flags);

            foreach (var Onebyte in vOut)
            {
                var flagByte = Convert.ToString(Onebyte, 2).PadLeft(12, '0');

                Reserved        = $"{flagByte.Substring(0, 3)}. .... .... Reserved bit: {(flagByte.Substring(0, 3) != "000" ? "Set" : "Not Set")}";
                Nonce           = $"...{flagByte.Substring(3, 1)} .... .... Nonce: {(flagByte.Substring(3, 1) == "1" ? "Set" : "Not Set")}";
                Congestion      = $".... {flagByte.Substring(4, 1)}... .... Congestion: {(flagByte.Substring(4, 1) == "1" ? "Set" : "Not Set")}";
                ECNEcho         = $".... .{flagByte.Substring(5, 1)}.. .... ECN-Echo: {(flagByte.Substring(5, 1) == "1" ? "Set" : "Not Set")}";
                Urgent          = $".... ..{flagByte.Substring(6, 1)}. .... Urgent: {(flagByte.Substring(6, 1) == "1" ? "Set" : "Not Set")}";
                Acknowledgment  = $".... ...{flagByte.Substring(7, 1)} ....  Acknowledgment: {(flagByte.Substring(7, 1) == "1" ? "Set" : "Not Set")}";
                Push            = $".... .... {flagByte.Substring(8, 1)}...  Push: {(flagByte.Substring(8, 1) == "1" ? "Set" : "Not Set")}";
                Reset           = $".... .... .{flagByte.Substring(9, 1)}..  Reset: {(flagByte.Substring(9, 1) == "1" ? "Set" : "Not Set")}";
                Syn             = $".... .... ..{flagByte.Substring(10, 1)}.  Syn: {(flagByte.Substring(10, 1) == "1" ? "Set" : "Not Set")}";
                Fin             = $".... .... ...{flagByte.Substring(11, 1)}  Fin: {(flagByte.Substring(11, 1) == "1" ? "Set" : "Not Set")}";
            }
        }
    }
}
