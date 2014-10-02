// POC.Network.Sniffer
// MainWindow.xaml.cs
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

using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using POC.Network.Sniffer.Enums;
using POC.Network.Sniffer.Helpers;
using POC.Network.Sniffer.Models;

namespace POC.Network.Sniffer
{
    public partial class MainWindow
    {
        public static MainWindow View;
        public byte[] Data = new byte[4096];

        public MainWindow()
        {
            InitializeComponent();
            View = this;
        }

        public Socket Socket { get; set; }
        public bool IsCapturing { get; set; }

        private void SnifferControl_OnClick(object sender, RoutedEventArgs e)
        {
            if (SnifferNetworkSelect.Text == "")
            {
                return;
            }
            try
            {
                switch (IsCapturing)
                {
                    case true:
                        IsCapturing = false;
                        SnifferControl.Content = "Start";
                        Socket.Close();
                        break;
                    case false:
                        Socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                        Socket.Bind(new IPEndPoint(IPAddress.Parse(SnifferNetworkSelect.Text), 0));
                        Socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                        var isTrue = new byte[4]
                        {
                            1, 0, 0, 0
                        };
                        var isOut = new byte[4]
                        {
                            1, 0, 0, 0
                        };
                        Socket.IOControl(IOControlCode.ReceiveAll, isTrue, isOut);
                        Socket.BeginReceive(Data, 0, Data.Length, SocketFlags.None, OnReceive, null);
                        IsCapturing = true;
                        SnifferControl.Content = "Stop";
                        break;
                }
            }
            catch (Exception ex)
            {
            }
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                var nReceived = Socket.EndReceive(ar);
                var copied = new byte[4096];
                Array.Copy(Data, 0, copied, 0, 4096);
                DispatcherHelper.Invoke(() => ParseData(copied, nReceived));
                if (!IsCapturing)
                {
                    return;
                }
                Data = new byte[4096];
                Socket.BeginReceive(Data, 0, Data.Length, SocketFlags.None, OnReceive, null);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
            }
        }

        private void ParseData(byte[] byteData, int nReceived)
        {
            var rootTreeViewItem = new TreeViewItem();
            var ipHeader = new IPHeader(byteData, nReceived);
            var ipTreeViewItem = TreeViewHelper.MakeIPTreeViewItem(ipHeader);
            rootTreeViewItem.Items.Add(ipTreeViewItem);
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    var tcpHeader = new TCPHeader(ipHeader.Data.ToArray(), ipHeader.MessageLength);
                    if (tcpHeader.Data.Any())
                    {
                        var tcpTreeViewItem = TreeViewHelper.MakeTCPTreeViewItem(tcpHeader);
                        var tcpData = new StringBuilder();
                        foreach (var b in tcpHeader.Data)
                        {
                            tcpData.AppendFormat("{0} ", b.ToString("X"));
                        }
                        tcpTreeViewItem.Items.Add("Data Length: " + tcpHeader.Data.Count);
                        tcpTreeViewItem.Items.Add("Data: " + tcpData.ToString()
                                                                    .Trim());
                        rootTreeViewItem.Items.Add(tcpTreeViewItem);
                        if (tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53")
                        {
                            var dnsNode = TreeViewHelper.MakeDNSTreeViewItem(tcpHeader.Data.ToArray(), (int) tcpHeader.MessageLength);
                            rootTreeViewItem.Items.Add(dnsNode);
                        }
                    }
                    break;
                case Protocol.UDP:
                    var udpHeader = new UDPHeader(ipHeader.Data.ToArray(), (int) ipHeader.MessageLength);
                    var udpTreeViewItem = TreeViewHelper.MakeUDPTreeViewItem(udpHeader);
                    var udpData = new StringBuilder();
                    foreach (var b in udpHeader.Data)
                    {
                        udpData.AppendFormat("{0} ", b.ToString("X"));
                    }
                    udpTreeViewItem.Items.Add("Data Length: " + udpHeader.Data.Count);
                    udpTreeViewItem.Items.Add("Data: " + udpData.ToString()
                                                                .Trim());
                    rootTreeViewItem.Items.Add(udpTreeViewItem);
                    if (udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53")
                    {
                        var dnsNode = TreeViewHelper.MakeDNSTreeViewItem(udpHeader.Data.ToArray(), Convert.ToInt32(udpHeader.Length) - 8);
                        rootTreeViewItem.Items.Add(dnsNode);
                    }
                    break;
                case Protocol.Unknown:
                    break;
            }
            rootTreeViewItem.Header = ipHeader.SourceAddress.ToString() + "-" + ipHeader.DestinationAddress.ToString();
            TreeViewHelper.AddTreeViewItem(rootTreeViewItem);
        }

        private void MainWindow_OnLoaded(object sender, RoutedEventArgs e)
        {
            var hosyEntry = Dns.GetHostEntry((Dns.GetHostName()));
            if (hosyEntry.AddressList.Length <= 0)
            {
                return;
            }
            foreach (var ip in hosyEntry.AddressList)
            {
                SnifferNetworkSelect.Items.Add(ip.ToString());
            }
        }

        private void MainWindow_OnClosed(object sender, EventArgs e)
        {
            try
            {
                Socket.Close();
            }
            catch (Exception ex)
            {
            }
        }
    }
}
