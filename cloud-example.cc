/*
 * Copyright (c) 2011 University of Kansas
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Modificato per supportare AODV e DSDV con TCP e UDP
 */

#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/packet-sink.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/yans-wifi-helper.h"

#include <fstream>
#include <iostream>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("manet-routing-compare");

class RoutingExperiment
{
  public:
    RoutingExperiment();
    void Run();
    void CommandSetup(int argc, char** argv);

  private:
    Ptr<Socket> SetupPacketReceive(Ipv4Address addr, Ptr<Node> node);
    void ReceivePacket(Ptr<Socket> socket);
    void CheckThroughput();
    void TrackPackets();

    uint32_t port{9};
    uint32_t bytesTotal{0};
    uint32_t packetsReceived{0};
    uint32_t packetsSent{0};
    uint32_t packetsLost{0};
    std::vector<Ptr<PacketSink>> sinks;

    std::string m_CSVfileName{"manet-routing.output.csv"};
    int m_nSinks{10};
    std::string m_protocolName{"AODV"};
    std::string m_trafficType{"UDP"};
    double m_txp{0.1};
    bool m_traceMobility{false};
    bool m_flowMonitor{false};
    Ptr<FlowMonitor> flowmon;
    FlowMonitorHelper flowmonHelper;
};

RoutingExperiment::RoutingExperiment()
{
}

static inline std::string
PrintReceivedPacket(Ptr<Socket> socket, Ptr<Packet> packet, Address senderAddress)
{
    std::ostringstream oss;

    oss << Simulator::Now().GetSeconds() << " " << socket->GetNode()->GetId();

    if (InetSocketAddress::IsMatchingType(senderAddress))
    {
        InetSocketAddress addr = InetSocketAddress::ConvertFrom(senderAddress);
        oss << " received one packet from " << addr.GetIpv4();
    }
    else
    {
        oss << " received one packet!";
    }
    return oss.str();
}

void
RoutingExperiment::ReceivePacket(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address senderAddress;
    while ((packet = socket->RecvFrom(senderAddress)))
    {
        bytesTotal += packet->GetSize();
        packetsReceived += 1;
        NS_LOG_UNCOND(PrintReceivedPacket(socket, packet, senderAddress));
    }
}

void
RoutingExperiment::TrackPackets()
{
    if (m_flowMonitor && flowmon)
    {
        flowmon->CheckForLostPackets();
        Ptr<Ipv4FlowClassifier> classifier =
            DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
        FlowMonitor::FlowStatsContainer stats = flowmon->GetFlowStats();

        packetsSent = 0;
        packetsLost = 0;

        for (auto iter = stats.begin(); iter != stats.end(); ++iter)
        {
            packetsSent += iter->second.txPackets;
            packetsLost += iter->second.lostPackets;
        }
    }

    // Schedule next check
    Simulator::Schedule(Seconds(1), &RoutingExperiment::TrackPackets, this);
}

void
RoutingExperiment::CheckThroughput()
{
    // Per UDP utilizziamo i contatori che abbiamo già
    uint64_t totalBytes = bytesTotal;
    uint32_t totalPackets = packetsReceived;

    // Per TCP, sommiamo i totali di tutti i sink TCP
    if (m_trafficType == "TCP" && !sinks.empty())
    {
        totalBytes = 0;
        for (auto& sink : sinks)
        {
            totalBytes += sink->GetTotalRx();
            // Stima dei pacchetti per TCP
            totalPackets = totalBytes / 1024;
        }
    }

    double kbs = (totalBytes * 8.0) / 1000;

    // Reset per UDP solo (TCP viene già gestito dai sink)
    if (m_trafficType == "UDP")
    {
        bytesTotal = 0;
    }

    std::ofstream out(m_CSVfileName, std::ios::app);

    out << (Simulator::Now()).GetSeconds() << "," << kbs << "," << packetsSent << "," << packetsLost
        << "," << m_protocolName << "," << m_trafficType << std::endl;

    out.close();

    Simulator::Schedule(Seconds(1), &RoutingExperiment::CheckThroughput, this);
}

Ptr<Socket>
RoutingExperiment::SetupPacketReceive(Ipv4Address addr, Ptr<Node> node)
{
    TypeId tid;
    if (m_trafficType == "UDP")
    {
        tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> sink = Socket::CreateSocket(node, tid);
        InetSocketAddress local = InetSocketAddress(addr, port);
        sink->Bind(local);
        sink->SetRecvCallback(MakeCallback(&RoutingExperiment::ReceivePacket, this));
        return sink;
    }

    // Per TCP, il PacketSinkHelper gestisce la ricezione
    return nullptr;
}

void
RoutingExperiment::CommandSetup(int argc, char** argv)
{
    CommandLine cmd(__FILE__);
    cmd.AddValue("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
    cmd.AddValue("traceMobility", "Enable mobility tracing", m_traceMobility);
    cmd.AddValue("protocol", "Routing protocol (AODV, DSDV)", m_protocolName);
    cmd.AddValue("trafficType", "Traffic type (TCP/UDP)", m_trafficType);
    cmd.AddValue("nSinks", "Number of sink nodes", m_nSinks);
    cmd.AddValue("txp", "Transmission power in dBm", m_txp);
    cmd.AddValue("flowMonitor", "Enable FlowMonitor", m_flowMonitor);
    cmd.Parse(argc, argv);

    std::vector<std::string> allowedProtocols{"AODV", "DSDV"};
    std::vector<std::string> allowedTrafficTypes{"TCP", "UDP"};

    if (std::find(allowedProtocols.begin(), allowedProtocols.end(), m_protocolName) ==
        allowedProtocols.end())
    {
        NS_FATAL_ERROR("Protocollo non supportato: " << m_protocolName
                                                     << ". Utilizzare AODV o DSDV.");
    }

    if (std::find(allowedTrafficTypes.begin(), allowedTrafficTypes.end(), m_trafficType) ==
        allowedTrafficTypes.end())
    {
        NS_FATAL_ERROR("Tipo di traffico non supportato: " << m_trafficType
                                                           << ". Utilizzare TCP o UDP.");
    }

    // Configurazioni specifiche per TCP
    if (m_trafficType == "TCP")
    {
        Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1024));
        Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(131072));
        Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(131072));
    }
}

int
main(int argc, char* argv[])
{
    RoutingExperiment experiment;
    experiment.CommandSetup(argc, argv);
    experiment.Run();
    return 0;
}

void
RoutingExperiment::Run()
{
    Packet::EnablePrinting();

    std::ofstream out(m_CSVfileName);
    out << "SimulationSecond,"
        << "ReceiveRate,"
        << "PacketsSent,"
        << "PacketsLost,"
        << "RoutingProtocol,"
        << "TrafficType" << std::endl;
    out.close();

    int nWifis = 50;
    double TotalTime = 200.0;
    std::string rate("2048bps");
    std::string phyMode("DsssRate11Mbps");
    std::string tr_name("manet-routing-compare");
    int nodeSpeed = 20;
    int nodePause = 0;

    Config::SetDefault("ns3::OnOffApplication::PacketSize", StringValue("64"));
    Config::SetDefault("ns3::OnOffApplication::DataRate", StringValue(rate));
    Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(phyMode));

    NodeContainer adhocNodes;
    adhocNodes.Create(nWifis);

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);

    YansWifiPhyHelper wifiPhy;
    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::FriisPropagationLossModel");
    wifiPhy.SetChannel(wifiChannel.Create());

    WifiMacHelper wifiMac;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue(phyMode),
                                 "ControlMode",
                                 StringValue(phyMode));

    wifiPhy.Set("TxPowerStart", DoubleValue(m_txp));
    wifiPhy.Set("TxPowerEnd", DoubleValue(m_txp));

    wifiMac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer adhocDevices = wifi.Install(wifiPhy, wifiMac, adhocNodes);

    MobilityHelper mobilityAdhoc;
    int64_t streamIndex = 0;

    ObjectFactory pos;
    pos.SetTypeId("ns3::RandomRectanglePositionAllocator");
    pos.Set("X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));
    pos.Set("Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"));

    Ptr<PositionAllocator> taPositionAlloc = pos.Create()->GetObject<PositionAllocator>();
    streamIndex += taPositionAlloc->AssignStreams(streamIndex);

    std::stringstream ssSpeed;
    ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
    std::stringstream ssPause;
    ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
    mobilityAdhoc.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                   "Speed",
                                   StringValue(ssSpeed.str()),
                                   "Pause",
                                   StringValue(ssPause.str()),
                                   "PositionAllocator",
                                   PointerValue(taPositionAlloc));
    mobilityAdhoc.SetPositionAllocator(taPositionAlloc);
    mobilityAdhoc.Install(adhocNodes);
    streamIndex += mobilityAdhoc.AssignStreams(adhocNodes, streamIndex);

    AodvHelper aodv;
    DsdvHelper dsdv;
    Ipv4ListRoutingHelper list;
    InternetStackHelper internet;

    if (m_protocolName == "AODV")
    {
        list.Add(aodv, 100);
        internet.SetRoutingHelper(list);
        internet.Install(adhocNodes);
    }
    else if (m_protocolName == "DSDV")
    {
        list.Add(dsdv, 100);
        internet.SetRoutingHelper(list);
        internet.Install(adhocNodes);
    }

    NS_LOG_INFO("Assegnazione indirizzi IP");
    Ipv4AddressHelper addressAdhoc;
    addressAdhoc.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer adhocInterfaces;
    adhocInterfaces = addressAdhoc.Assign(adhocDevices);

    // Svuota il vettore dei sink
    sinks.clear();

    for (int i = 0; i < m_nSinks; i++)
    {
        // Setup packet receive per UDP
        if (m_trafficType == "UDP")
        {
            Ptr<Socket> sink = SetupPacketReceive(adhocInterfaces.GetAddress(i), adhocNodes.Get(i));
        }

        AddressValue remoteAddress(InetSocketAddress(adhocInterfaces.GetAddress(i), port));
        Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable>();

        if (m_trafficType == "UDP")
        {
            OnOffHelper onoff1("ns3::UdpSocketFactory", Address());
            onoff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff1.SetAttribute("OffTime",
                                StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
            onoff1.SetAttribute("Remote", remoteAddress);

            ApplicationContainer temp = onoff1.Install(adhocNodes.Get(i + m_nSinks));
            temp.Start(Seconds(var->GetValue(100.0, 101.0)));
            temp.Stop(Seconds(TotalTime));
        }
        else // TCP
        {
            // Install TCP Sink on receiver node
            PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                        InetSocketAddress(Ipv4Address::GetAny(), port));
            ApplicationContainer sinkApp = sinkHelper.Install(adhocNodes.Get(i));

            // Aggiungi il sink al vettore per il monitoraggio
            Ptr<PacketSink> packetSink = DynamicCast<PacketSink>(sinkApp.Get(0));
            sinks.push_back(packetSink);

            sinkApp.Start(Seconds(0.0));
            sinkApp.Stop(Seconds(TotalTime));

            // Install TCP BulkSend on sender node
            BulkSendHelper source("ns3::TcpSocketFactory", remoteAddress.Get());
            source.SetAttribute("MaxBytes", UintegerValue(0)); // Unlimited data transfer

            ApplicationContainer sourceApp = source.Install(adhocNodes.Get(i + m_nSinks));
            sourceApp.Start(Seconds(var->GetValue(100.0, 101.0)));
            sourceApp.Stop(Seconds(TotalTime));
        }
    }

    AsciiTraceHelper ascii;
    MobilityHelper::EnableAsciiAll(ascii.CreateFileStream(tr_name + ".mob"));

    if (m_flowMonitor)
    {
        flowmon = flowmonHelper.InstallAll();
    }

    NS_LOG_INFO("Avvio simulazione.");
    CheckThroughput();
    TrackPackets();

    Simulator::Stop(Seconds(TotalTime));
    Simulator::Run();

    if (m_flowMonitor)
    {
        flowmon->SerializeToXmlFile(tr_name + ".flowmon", false, false);
    }

    Simulator::Destroy();
}