/**
 * Class that retrieves information from the TCP packets.
 * When there's an attack, then it will block the suspicious traffic
 * @author Laura Victoria Morales Medina: l.morales825@uniandes.edu.co
 */
package net.floodlightcontroller.headerextract;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFBufferId;

import net.floodlightcontroller.DDoSFinder.ChiSquare;
import net.floodlightcontroller.DDoSFinder.CorrelationMatrix;
import net.floodlightcontroller.DDoSFinder.IDDoSFinder;
import net.floodlightcontroller.DDoSFinder.ShannonsEntropy;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

public class HeaderExtract implements IOFMessageListener, IFloodlightModule {

	public final int DEFAULT_CACHE_SIZE = 10;

	/**
	 * Interval window
	 */
	private final static int INTERVAL_TIME = 5000; //5 seconds
	
	/**
	 * Covariance Matrix Method
	 */
	private final static String COVARIANCE_MATRIX = "CovarianceMatrix";
	
	/**
	 * Shannon's Entropy Method
	 */
	private final static String SHANNONS_ENTROPY = "ShannonsEntropy";
	
	/**
	 * Chi-Square Test Method
	 */
	private final static String CHI_SQUARE = "ChiSquare";

	/**
	 * Detection algorithm
	 */
	private String method;
	
	/**
	 * Floodlight Provider Service instance
	 */
	protected IFloodlightProviderService floodlightProviderIn;
	
	/**
	 * Flow Static Pusher instance (We'll use it if there's an attack)
	 */
	protected IStaticFlowEntryPusherService flowEntryPusherService;
	
	/**
	 * Device Manager to get the Switch associated with a Server
	 */
	protected IDeviceService deviceService;
	
	/**
	 * SwitchServer to get an switch to get it-s factory version
	 */
	protected IOFSwitchService switchService;

	/**
	 * Array that saves all the info
	 */
	private ArrayList<ServerInfo> serversInfo;

	/**
	 * Sending Thread. 
	 */
	private Thread sendingThread;

	/**
	 * Atribute that will detect DDoS
	 */
	private IDDoSFinder finder;
	
	/**
	 * Checks if the list has information or not
	 */
	private boolean hasInfo;

	/**
	 * Checks if there's enough info to send to detect attack
	 */
	private boolean sendInfo;
	
	private File outFile;
	
	private PrintWriter pw;
	

	//------------------------------------------------
	// Methods from the interfaces
	//------------------------------------------------

	@Override
	public String getName() {
		return "HeaderExtract";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> collection = new ArrayList<Class<? extends IFloodlightService>>();
		collection.add(IFloodlightProviderService.class);
		collection.add(IStaticFlowEntryPusherService.class);
		collection.add(IDeviceService.class);
		collection.add(IOFSwitchService.class);
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProviderIn = context.getServiceImpl(IFloodlightProviderService.class);
		flowEntryPusherService = context.getServiceImpl(IStaticFlowEntryPusherService.class);
		deviceService = context.getServiceImpl(IDeviceService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		serversInfo = new ArrayList<ServerInfo>();
		hasInfo = false;
		sendInfo = false;
		outFile = new File("/home/estudiante/register.txt");
		try {
			pw = new PrintWriter(outFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
		//We decide which algorithm we're going to use
		method = CHI_SQUARE; 
		
		readServer();

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		
		floodlightProviderIn.addOFMessageListener(OFType.PACKET_IN, this);	
		
		if(method.equals(COVARIANCE_MATRIX))
			finder = new CorrelationMatrix();
		else if(method.equals(SHANNONS_ENTROPY))
			finder = new ShannonsEntropy();
		else if(method.equals(CHI_SQUARE))
			finder = new ChiSquare();
		
		//A new Thread that every 5 seconds will send the information to the DDoS Finder
		sendingThread = new Thread(new Runnable() {
			int i = 0;
			boolean hasFlow = false;
			int flowindex = 0;
			int totalFlows = 0;
			@Override
			public void run() {
				while(true)
				{
					try 
					{
						Thread.sleep(INTERVAL_TIME);
						i++;
						flowindex++;
						if(flowindex == 60) //We erase any flow after a minute passed
						{
							if(hasFlow)
							{
								for (int j = 0; j < totalFlows; j++) 
								{
									String flowName = "DDoSDropFlow"+j;
									flowEntryPusherService.deleteFlow(flowName);
								}
								hasFlow = false;
							}
						}
						//Checks if we have any info to send to the next module
						if(hasInfo)
						{
							finder.receiveInfo(i, serversInfo);							
							cleanInfo();	
							hasInfo = false;
							sendInfo = true;
						}
						System.out.println("[HEADER_EXTRACT] 5 seconds has passed");
						if(i == 4)
						{
							System.out.println("20 seconds has passed!!!!!!");
							//Checks if we have enough info to apply the algorithm
							if(sendInfo)
							{
								System.out.println("[HEADER_EXTRACT] Sending Info");
								
								long t1 = System.currentTimeMillis();
								//We get the list of posibble attacked IP addresses
								ArrayList<String> possibleAttacked = finder.lookForAnAttack();
								//If the list is not empty, then we install the flows rules into the switches related to the attacked servers
								if(!possibleAttacked.isEmpty())
								{
									
									totalFlows = createFlow(possibleAttacked);
									hasFlow = true;
									flowindex = 0;
								}
								long t2 = System.currentTimeMillis();
								long totalTime = t2 - t1;
								System.out.println("Algorithm Time: "+totalTime);
								cleanInfo();
								sendInfo = false;
							}
							i = 0;
						}
					} 
					catch (InterruptedException e) 
					{
						e.printStackTrace();
					}
				}
			}
		});
		sendingThread.start();
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		//Get the Ethernet packet
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		//Gets the information from the eth packet
		getInfo(eth);
		
		return Command.CONTINUE;

	}

	//----------------------------------------------
	// Support Methods
	//----------------------------------------------

	/**
	 * Method that reads the file that contains the server's IP
	 */
	public void readServer()
	{
		try 
		{
			File file = new File("/home/estudiante/floodlight/data/servers.txt");
			BufferedReader br = new BufferedReader(new FileReader(file));
			String line = br.readLine();
			while(line != null)
			{
				if(!line.equals(""))
				{
					ServerInfo servInf = new ServerInfo(line);
					serversInfo.add(servInf);
				}
				line = br.readLine();
			}
			br.close();
		} 
		catch (Exception e) 
		{
			System.out.println("[ERROR]"+e.getMessage());
			e.printStackTrace();
		}
	}
	
	/**
	 * It will get the information from the ethernet packets that arrive
	 * @param eth
	 */
	public void getInfo(Ethernet eth)
	{
		if(eth.getPayload() instanceof IPv4)
		{
			IPv4 ipv4Pkt = (IPv4)eth.getPayload();
			//Gets the server associate with the IP
			ServerInfo server = getServerInfo(ipv4Pkt.getDestinationAddress().toString(), ipv4Pkt.getSourceAddress().toString());
			if(ipv4Pkt.getPayload() instanceof TCP)
			{
				//Checks if it is a TCP packet, if it is, then we will get the info
				TCP tcpPkt = (TCP)ipv4Pkt.getPayload();
				//Checks for the flags
				if(server != null)
				{
//					System.out.println("[HEADER_EXTRACT] TCP Pakcet flag = "+tcpPkt.getFlags());
//					System.out.println("[HEADER_EXTRACT] IP Source: "+ipv4Pkt.getSourceAddress());
					switch (tcpPkt.getFlags()) 
					{
					case 2: //SYN Flag
						server.addSYN();
						//Adds the source IP to the list
						boolean temp = server.addIpSrc(ipv4Pkt.getSourceAddress().toString());
						break;
					case 18: //SYN-ACK Flag
						server.addSYNACK();
						break;
					case 1: //FIN Flag
						if(ipv4Pkt.getDestinationAddress().toString().equals(server.getIp()))
							server.addFIN();							//We only add the FIN flag if the user sends it
						break;
					case 4://RST Flag
						server.addRST();
						break;
					case 17: //FIN-ACK Flag
						if(ipv4Pkt.getDestinationAddress().toString().equals(server.getIp()))
							server.addFINACK();							//We only add the FIN ACK flag if the user sends it
						break;
					case 16: //ACK Flag
						server.deleteActiveConnection(ipv4Pkt.getSourceAddress().toString());
						break;
					default:
						break;
					}
					hasInfo = true;
//					System.out.println("[HEADER-EXTRACT] Actual server information: "+server.toString());
				}
			}
		}
	}

	/**
	 * Method that looks for a server
	 * @return The server with the IP
	 *         Null if there-s not a server with that IP
	 */
	public ServerInfo getServerInfo(String ipIn, String ipOut)
	{
		for (int i = 0; i < serversInfo.size(); i++) 
		{
			ServerInfo serv = serversInfo.get(i);
			if(serv.getIp().equals(ipIn) || serv.getIp().equals(ipOut))
				return serv;
		}
		return null;
	}

	/**
	 * Method that cleans all the information
	 */
	public void cleanInfo()
	{
		for (int i = 0; i <serversInfo.size(); i++) 
		{
			ServerInfo serv = serversInfo.get(i);
			serv.clean();
		}
	}
	
	/**
	 * Creates the Flow that drops the traffic
	 * @param serversUnderAttack - List of the Servers that are under attack
	 * @returns the total count of flows installed
	 */
	public int createFlow(ArrayList<String> serversUnderAttack)
	{
		System.out.println("Enters CreateFlow");
		System.out.println("Servers under attack: "+serversUnderAttack.size());
		int totalRules = 0;
		for (int i = 0; i < serversUnderAttack.size(); i++) 
		{
			String serverIp = serversUnderAttack.get(i);
			Iterator<? extends IDevice> iterator = deviceService.queryDevices(null, null, IPv4Address.of(serverIp), null, null);
			while(iterator.hasNext())
			{
				IDevice device = iterator.next();
				System.out.println("[CREATE_FLOW] Get Device: "+device.getMACAddressString());
				System.out.println("[CREATE_FLOW] Get Device Switch: "+device.getAttachmentPoints().length);
				SwitchPort[] ports = device.getAttachmentPoints();
				for (int j = 0; j < ports.length; j++) 
				{
					SwitchPort port = ports[j];
					DatapathId switchDPID = port.getSwitchDPID();
					System.out.println("[CREATE_FLOW] Switch ID: "+port.getSwitchDPID().toString());
					IOFSwitch sw = switchService.getSwitch(switchDPID);
					OFFactory factory = sw.getOFFactory();
					
					ServerInfo serverTemp = getServerInfo(serverIp, "");
					ArrayList<String> dangerousIps = serverTemp.getUnsafeHosts();
					for (int k = 0; k < dangerousIps.size(); k++) 
					{
						System.out.println("[CREATE_FLOW] Create flow for IP: "+dangerousIps.get(k));
						String dangerIp = dangerousIps.get(k);
						Match match = factory.buildMatch()
								.setExact(MatchField.ETH_TYPE, EthType.IPv4)
								.setExact(MatchField.IPV4_DST, IPv4Address.of(serverIp))
								.setExact(MatchField.IPV4_SRC, IPv4Address.of(dangerIp))
								.build();
						OFFlowAdd flowAdd = factory.buildFlowAdd()
								.setBufferId(OFBufferId.NO_BUFFER)
								.setHardTimeout(3600)
								.setIdleTimeout(10)
								.setPriority(32768)
								.setMatch(match)
								.build();
						String flowName = "DDoSDropFlow"+totalRules;
						flowEntryPusherService.addFlow(flowName,flowAdd,switchDPID);
						totalRules++;
					}
				}
			}
		}
		return totalRules;
	}
	
	public void executeCommand(String message)
	{
		try {
			pw.println(message);
			Process p = Runtime.getRuntime().exec("smem -t | grep java");
			System.out.println("Execute command");
			p.waitFor();
			BufferedReader bf = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String line = "";
			while((line = bf.readLine())!= null)
			{
				if(line.contains("java"))
				{
					pw.println(line);
					System.out.println(line);					
				}
			}
			pw.flush();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	

}

