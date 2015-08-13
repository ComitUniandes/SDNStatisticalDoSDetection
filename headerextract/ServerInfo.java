/**
 * This class represents the information that the controller will extract per server.
 */
package net.floodlightcontroller.headerextract;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;

public class ServerInfo 
{
	/**
	 * Total SYN Flags
	 */
	private int SYNflags;
	
	/**
	 * Total SYN-ACK Flags
	 */
	private int SYNACKflags;
	
	/**
	 * Total FIN Flags
	 */
	private int FINflags;
	
	/**
	 * Total RST Flags
	 */
	private int RSTflags;
	
	/**
	 * Total FIN-ACK FLags
	 */
	private int FINACKflags;
	
	/**
	 * Hashing table that contains all the info about the hosts that make a request to this server
	 * Key: IPAddress
	 * Value: Host
	 */
	private Hashtable<String, Host> hosts;
	
	/**
	 * The Server IP
	 */
	private String ip;

	/**
	 * Class Constructor
	 * @param ip
	 */
	public ServerInfo(String ip) {
		super();
		SYNflags = 0;
		SYNACKflags = 0;
		FINflags = 0;
		RSTflags = 0;
		FINACKflags = 0;
		hosts = new Hashtable<String, Host>();
		this.ip = ip;
	}

	public int getSYNflags() {
		return SYNflags;
	}

	public int getSYNACKflags() {
		return SYNACKflags;
	}

	public int getFINflags() {
		return FINflags;
	}

	public int getRSTflags() {
		return RSTflags;
	}

	public int getFINACKflags() {
		return FINACKflags;
	}
	
	public String getIp() {
		return ip;
	}
	
	public void addFINACK()
	{
		FINACKflags++;
	}
	
	public void addFIN()
	{
		FINflags++;
	}
	
	public void addRST()
	{
		RSTflags++;
	}

	public void addSYNACK()
	{
		SYNACKflags++;
	}
	
	public void addSYN()
	{
		SYNflags++;
	}
	
	/**
	 * Add a new Host to the list
	 * @param ipAddr = The new IPAddress
	 * @return true - if the new IP was added, false - otherwise
	 */
	public boolean addIpSrc(String ipAddr)
	{
		//Checks if the server has the IP Address
		if(this.ip.equals(ipAddr))
			return false;
		else
		{
			//Looks if there's a host with the IP address
			Host host = hosts.get(ipAddr);
			if(host == null)
			{
				//If there's not an object with that key, then will add a new one
				host = new Host(ipAddr);
				hosts.put(ipAddr, host);	
				host.addConnection();
				return true;
			}
			else
			{
				//Else, we increase the number of total connections
				host.addConnection();
				return false;
			}
		}
	}
	
	/**
	 * Returns a list with the "unsafe" IPAddress
	 * @return a list with the IP list
	 */
	public ArrayList<String> getUnsafeHosts()
	{
		ArrayList<String> list = new ArrayList<String>();
		Iterator<Host> iterator = hosts.values().iterator();
		while(iterator.hasNext())
		{
			Host toAdd = iterator.next();
			if(!toAdd.isSafe())
				list.add(toAdd.getIpAddress());
		}
		return list;
	}
	
	/**
	 * Deletes an active connection from the host with the ipAddress
	 * @param ipAddress
	 */
	public void deleteActiveConnection(String ipAddress)
	{
		Host host = hosts.get(ipAddress);
		if(host != null)
		{
			if(host.getIsWaitingAck())
			{
				System.out.println("[HEADER_EXTRACT] ServerInfo, deleteActiveConnection: "+host.getIpAddress());
				host.deleteActiveConnection();	
			}
		}
	}
	
	/**
	 * To String method
	 */
	@Override
	public String toString() 
	{
		String resp = "Server info: \n" +
				"\n SYN Flags: "+SYNflags+
				"\n SYN-ACK Flags: "+SYNACKflags+
				"\n FIN Flags: "+FINflags+
				"\n FIN-ACK Flags: "+FINACKflags+
				"\n Ip Address: "+ip+
				"\n Ips Soruce Information: ";
		Iterator<Host> iterator = hosts.values().iterator();
		while(iterator.hasNext())
		{
			resp += iterator.next().toString();
		}
		return resp;
	}
	
	/**
	 * Sets all the values into 0
	 */
	public void clean()
	{
		SYNflags = 0;
		SYNACKflags = 0;
		FINflags = 0;
		FINACKflags = 0;
		RSTflags = 0;
	}
	
	/**
	 * Class that represent's a Host
	 * It counts the times that a Host has made a request
	 */
	private class Host
	{
		private String ipAddress;
		
		private double activeConnections;
		
		private double totalConnections;
		
		private boolean isSafe;
		
		private boolean waitingForAck;
		
		public Host(String ipAddress)
		{
			this.ipAddress = ipAddress;
			activeConnections = 0;
			totalConnections = 0;
			waitingForAck = true;
			isSafe = false;
		}

		public String getIpAddress() {
			return ipAddress;
		}
		
		public boolean getIsWaitingAck()
		{
			return waitingForAck;
		}

		public boolean isSafe() 
		{
//			if(!isSafe)
//				return false;
//			else
//			{
//				double connectionRate = activeConnections/totalConnections;
//				if(connectionRate >= 0 && connectionRate <= 0.02)
//					return true;
//				else
//					return false;
//			}
			return isSafe;
		}
		
		public void addConnection(){
			waitingForAck = true;
			activeConnections ++;
			totalConnections ++;
		}
		
		public void deleteActiveConnection(){
			activeConnections --;
			isSafe = true;
			waitingForAck = false;
		}
		
		public String toString()
		{
			String resp = "";
			resp += "Ip Address: "+ipAddress+
					"\n Total Connections: "+totalConnections+
					"\n Active Connections: "+activeConnections;
			return resp;
		}
	}
}
