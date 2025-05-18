#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/packet-sink.h"

#include <fstream>
#include <iostream>
#include <vector>

using namespace ns3;
using namespace dsr;

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
    void PacketSent(Ptr<const Packet> packet);

    uint32_t port{9};
    uint32_t bytesTotal{0};
    uint32_t packetsReceived{0};
    uint32_t packetsSent{0};
    uint32_t previousSent{0};
    uint32_t previousReceived{0};
    uint32_t previousTcpLost{0};
    std::vector<Ptr<PacketSink>> sinks;

    std::string m_CSVfileName{"manet-routing.output.csv"};
    int m_nSinks{10};
    int m_nNodes{50};
    std::string m_protocolName{"AODV"};
    std::string m_trafficType{"UDP"};
    double m_txp{0.1};
    bool m_traceMobility{false};
    bool m_flowMonitor{false};

    Ptr<FlowMonitor> flowmon;
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
RoutingExperiment::PacketSent(Ptr<const Packet> packet)
{
    packetsSent++;
}

void
RoutingExperiment::CheckThroughput()
{
    double kbs = 0.0;
    uint32_t totalPackets = 0;
    uint32_t lost = 0;

    if (m_trafficType == "UDP")
    {
        uint32_t sentInInterval = packetsSent - previousSent;
        uint32_t receivedInInterval = packetsReceived - previousReceived;
        lost = sentInInterval - receivedInInterval;

        previousSent = packetsSent;
        previousReceived = packetsReceived;

        kbs = (bytesTotal * 8.0) / 1000;
        totalPackets = receivedInInterval;

        // Reset solo bytesTotal, ma manteniamo packetsReceived e packetsSent per il calcolo corretto degli intervalli
        bytesTotal = 0;
        // NON azzeriamo packetsReceived
    }
    else // TCP
    {
        uint64_t totalBytes = 0;
        for (auto& sink : sinks)
        {
            totalBytes += sink->GetTotalRx();
        }
        kbs = (totalBytes * 8.0) / 1000;
        totalPackets = totalBytes / 1024;

        if (flowmon)
        {
            flowmon->CheckForLostPackets();
            FlowMonitor::FlowStatsContainer stats = flowmon->GetFlowStats();
            uint32_t currentTcpLost = 0;
            for (auto& flow : stats)
            {
                currentTcpLost += flow.second.lostPackets;
            }
            lost = currentTcpLost - previousTcpLost;
            previousTcpLost = currentTcpLost;
        }
    }

    std::ofstream out(m_CSVfileName, std::ios::app);
    out << Simulator::Now().GetSeconds() << ","
        << kbs << ","
        << totalPackets << ","
        << lost << ","
        << m_nSinks << ","
        << m_protocolName << ","
        << m_txp << ","
        << m_trafficType << std::endl;
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
    return nullptr;
}

void
RoutingExperiment::CommandSetup(int argc, char** argv)
{
    CommandLine cmd(__FILE__);
    cmd.AddValue("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
    cmd.AddValue("traceMobility", "Enable mobility tracing", m_traceMobility);
    cmd.AddValue("protocol", "Routing protocol (OLSR, AODV, DSDV, DSR)", m_protocolName);
    cmd.AddValue("trafficType", "Traffic type (TCP/UDP)", m_trafficType);
    cmd.AddValue("flowMonitor", "Enable FlowMonitor", m_flowMonitor);
    cmd.AddValue("nSinks", "Number of sink nodes", m_nSinks);
    cmd.AddValue("nNodes", "Total number of nodes", m_nNodes);
    cmd.Parse(argc, argv);

    std::vector<std::string> allowedProtocols{"OLSR", "AODV", "DSDV", "DSR"};
    std::vector<std::string> allowedTrafficTypes{"TCP", "UDP"};

    if (std::find(allowedProtocols.begin(), allowedProtocols.end(), m_protocolName) == allowedProtocols.end())
    {
        NS_FATAL_ERROR("No such protocol:" << m_protocolName);
    }

    if (std::find(allowedTrafficTypes.begin(), allowedTrafficTypes.end(), m_trafficType) == allowedTrafficTypes.end())
    {
        NS_FATAL_ERROR("No such traffic type:" << m_trafficType);
    }

    // Validate that we have enough nodes for the requested sinks
    if (m_nSinks * 2 > m_nNodes)
    {
        NS_FATAL_ERROR("Error: Need at least " << m_nSinks * 2 << " nodes for " << m_nSinks << " sinks (source + sink)");
    }

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
        << "PacketsReceived,"
        << "LostPackets,"
        << "NumberOfSinks,"
        << "RoutingProtocol,"
        << "TransmissionPower,"
        << "TrafficType" << std::endl;
    out.close();

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
    adhocNodes.Create(m_nNodes);

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
    OlsrHelper olsr;
    DsdvHelper dsdv;
    DsrHelper dsr;
    DsrMainHelper dsrMain;
    Ipv4ListRoutingHelper list;
    InternetStackHelper internet;

    if (m_protocolName == "OLSR")
    {
        list.Add(olsr, 100);
        internet.SetRoutingHelper(list);
        internet.Install(adhocNodes);
    }
    else if (m_protocolName == "AODV")
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
    else if (m_protocolName == "DSR")
    {
        internet.Install(adhocNodes);
        dsrMain.Install(dsr, adhocNodes);
        if (m_flowMonitor)
        {
            NS_FATAL_ERROR("Error: FlowMonitor does not work with DSR. Terminating.");
        }
    }

    NS_LOG_INFO("Assigning IP address");
    Ipv4AddressHelper addressAdhoc;
    addressAdhoc.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer adhocInterfaces;
    adhocInterfaces = addressAdhoc.Assign(adhocDevices);

    sinks.clear();

    for (int i = 0; i < m_nSinks; i++)
    {
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
            onoff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
            onoff1.SetAttribute("Remote", remoteAddress);

            ApplicationContainer temp = onoff1.Install(adhocNodes.Get(i + m_nSinks));
            Ptr<Application> app = temp.Get(0);
            app->TraceConnectWithoutContext("Tx", MakeCallback(&RoutingExperiment::PacketSent, this));
            temp.Start(Seconds(var->GetValue(100.0, 101.0)));
            temp.Stop(Seconds(TotalTime));
        }
        else // TCP
        {
            PacketSinkHelper sinkHelper("ns3::TcpSocketFactory", 
                                      InetSocketAddress(Ipv4Address::GetAny(), port));
            ApplicationContainer sinkApp = sinkHelper.Install(adhocNodes.Get(i));
            Ptr<PacketSink> packetSink = DynamicCast<PacketSink>(sinkApp.Get(0));
            sinks.push_back(packetSink);
            sinkApp.Start(Seconds(0.0));
            sinkApp.Stop(Seconds(TotalTime));

            BulkSendHelper source("ns3::TcpSocketFactory", remoteAddress.Get());
            source.SetAttribute("MaxBytes", UintegerValue(0));
            ApplicationContainer sourceApp = source.Install(adhocNodes.Get(i + m_nSinks));
            sourceApp.Start(Seconds(var->GetValue(100.0, 101.0)));
            sourceApp.Stop(Seconds(TotalTime));
        }
    }

    AsciiTraceHelper ascii;
    MobilityHelper::EnableAsciiAll(ascii.CreateFileStream(tr_name + ".mob"));

    FlowMonitorHelper flowmonHelper;
    if (m_flowMonitor)
    {
        flowmon = flowmonHelper.InstallAll();
    }

    NS_LOG_INFO("Run Simulation.");
    CheckThroughput();
    Simulator::Stop(Seconds(TotalTime));
    Simulator::Run();

    if (m_flowMonitor)
    {
        flowmon->SerializeToXmlFile(tr_name + ".flowmon", false, false);
    }

    Simulator::Destroy();
}