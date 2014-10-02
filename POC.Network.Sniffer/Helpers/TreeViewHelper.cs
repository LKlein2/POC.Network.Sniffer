// POC.Network.Sniffer
// TreeViewHelper.cs
// 
// Copyright © 2007 - 2014 Ryan Wilson - All Rights Reserved
// 
// Redistribution and use in source and binary forms, with or without 
// modification, are permitted provided that the following conditions are met: 
// 
//  * Redistributions of source code must retain the above copyright notice, 
//    this list of conditions and the following disclaimer. 
//  * Redistributions in binary form must reproduce the above copyright 
//    notice, this list of conditions and the following disclaimer in the 
//    documentation and/or other materials provided with the distribution. 
//  * Neither the name of SyndicatedLife nor the names of its contributors may 
//    be used to endorse or promote products derived from this software 
//    without specific prior written permission. 
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE. 

using System.Windows.Controls;
using POC.Network.Sniffer.Enums;
using POC.Network.Sniffer.Models;

namespace POC.Network.Sniffer.Helpers
{
    public static class TreeViewHelper
    {
        public static TreeViewItem MakeIPTreeViewItem(IPHeader ipHeader)
        {
            var ipTreeViewItem = new TreeViewItem();
            ipTreeViewItem.Header = "IP";
            ipTreeViewItem.Items.Add("Ver: " + ipHeader.Version);
            ipTreeViewItem.Items.Add("Header Length: " + ipHeader.HeaderLength);
            ipTreeViewItem.Items.Add("Differntiated Services: " + ipHeader.DifferentiatedServices);
            ipTreeViewItem.Items.Add("Total Length: " + ipHeader.TotalLength);
            ipTreeViewItem.Items.Add("Identification: " + ipHeader.Identification);
            ipTreeViewItem.Items.Add("Flags: " + ipHeader.Flags);
            ipTreeViewItem.Items.Add("Fragmentation Offset: " + ipHeader.FragmentationOffset);
            ipTreeViewItem.Items.Add("Time to live: " + ipHeader.TTL);
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    ipTreeViewItem.Items.Add("Protocol: " + "TCP");
                    break;
                case Protocol.UDP:
                    ipTreeViewItem.Items.Add("Protocol: " + "UDP");
                    break;
                case Protocol.Unknown:
                    ipTreeViewItem.Items.Add("Protocol: " + "Unknown");
                    break;
            }
            ipTreeViewItem.Items.Add("Checksum: " + ipHeader.Checksum);
            ipTreeViewItem.Items.Add("Source: " + ipHeader.SourceAddress.ToString());
            ipTreeViewItem.Items.Add("Destination: " + ipHeader.DestinationAddress.ToString());
            return ipTreeViewItem;
        }

        public static TreeViewItem MakeTCPTreeViewItem(TCPHeader tcpHeader)
        {
            var tcpTreeViewItem = new TreeViewItem();
            tcpTreeViewItem.Header = "TCP";
            tcpTreeViewItem.Items.Add("Source Port: " + tcpHeader.SourcePort);
            tcpTreeViewItem.Items.Add("Destination Port: " + tcpHeader.DestinationPort);
            tcpTreeViewItem.Items.Add("Sequence Number: " + tcpHeader.SequenceNumber);
            if (tcpHeader.AcknowledgementNumber != "")
            {
                tcpTreeViewItem.Items.Add("Acknowledgement Number: " + tcpHeader.AcknowledgementNumber);
            }
            tcpTreeViewItem.Items.Add("Header Length: " + tcpHeader.HeaderLength);
            tcpTreeViewItem.Items.Add("Flags: " + tcpHeader.Flags);
            tcpTreeViewItem.Items.Add("Window Size: " + tcpHeader.WindowSize);
            tcpTreeViewItem.Items.Add("Checksum: " + tcpHeader.Checksum);
            if (tcpHeader.UrgentPointer != "")
            {
                tcpTreeViewItem.Items.Add("Urgent Pointer: " + tcpHeader.UrgentPointer);
            }
            return tcpTreeViewItem;
        }

        public static TreeViewItem MakeUDPTreeViewItem(UDPHeader udpHeader)
        {
            var udpTreeViewItem = new TreeViewItem();
            udpTreeViewItem.Header = "UDP";
            udpTreeViewItem.Items.Add("Source Port: " + udpHeader.SourcePort);
            udpTreeViewItem.Items.Add("Destination Port: " + udpHeader.DestinationPort);
            udpTreeViewItem.Items.Add("Length: " + udpHeader.Length);
            udpTreeViewItem.Items.Add("Checksum: " + udpHeader.Checksum);
            return udpTreeViewItem;
        }

        public static TreeViewItem MakeDNSTreeViewItem(byte[] byteData, int nLength)
        {
            var dnsHeader = new DNSHeader(byteData, nLength);
            var dnsTreeViewItem = new TreeViewItem();
            dnsTreeViewItem.Header = "DNS";
            dnsTreeViewItem.Items.Add("Identification: " + dnsHeader.Identification);
            dnsTreeViewItem.Items.Add("Flags: " + dnsHeader.Flags);
            dnsTreeViewItem.Items.Add("Questions: " + dnsHeader.TotalQuestions);
            dnsTreeViewItem.Items.Add("Answer RRs: " + dnsHeader.TotalAnswerRR);
            dnsTreeViewItem.Items.Add("Authority RRs: " + dnsHeader.TotalAuthorityRR);
            dnsTreeViewItem.Items.Add("Additional RRs: " + dnsHeader.TotalAdditionalRR);
            return dnsTreeViewItem;
        }

        public static void AddTreeViewItem(TreeViewItem node)
        {
            DispatcherHelper.Invoke(() => MainWindow.View.SnifferTV.Items.Add(node));
        }
    }
}
