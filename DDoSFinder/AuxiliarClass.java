package net.floodlightcontroller.DDoSFinder;

public abstract class AuxiliarClass 
{
	//------------------------------------
	// Attributes
	//------------------------------------
	
	/**
	 * Server's IP
	 */
	private String ip;
	
	/**
	 * How many SYN flags
	 */
	private double synFlags;
	
	/**
	 * How Many SYN-ACK flags
	 */
	private double synAckFlags;
	
	/**
	 * How Many FIN flags
	 */
	private double finFlags;
	
	/**
	 * Total Flags
	 */
	private double totalFlags;
	
	//------------------------------------
	// Constructor
	//------------------------------------
	
	/**
	 * Creates a new AuxiliarClass
	 * It will initialize the flags into 0
	 * Creates an empty IP list
	 * Assigns the IP
	 * @param serversIp - The server IP
	 */
	public AuxiliarClass(String serversIp)
	{
		this.ip = serversIp;
		synFlags = 0;
		synAckFlags = 0;
		finFlags = 0;
	}
	
	//------------------------------------
	// Methods
	//------------------------------------
	
	/**
	 * Adds the information necessary to detect an DDoS attack
	 * @param syn - Number of SYN Flags
	 * @param synAck - Number of SYN-ACK Flags
	 * @param rst - Number of RST Flags
	 * @param fin - Number of FIN Flags
	 * @param finAck - Number of FIN-ACK Flags
	 * @param index - The i-th observation
	 * @param ips - The list of Host's IPs that made a request to the server
	 */
	public void addData(int syn, int synAck, int rst, int fin, int finAck, int index)
	{
		synFlags += syn;
		synAckFlags += synAck;
		finFlags += fin+finAck;
		totalFlags = synFlags + synAckFlags + finFlags;
	}
	
	//------------------------------------
	// Getters and Setters
	//------------------------------------

	public String getIp() {
		return ip;
	}

	public void setIp(String ip) {
		this.ip = ip;
	}

	public double getSynFlags() {
		return synFlags;
	}

	public void setSynFlags(double synFlags) {
		this.synFlags = synFlags;
	}

	public double getSynAckFlags() {
		return synAckFlags;
	}

	public void setSynAckFlags(double synAckFlags) {
		this.synAckFlags = synAckFlags;
	}

	public double getFinFlags() {
		return finFlags;
	}

	public void setFinFlags(double finFlags) {
		this.finFlags = finFlags;
	}

	public double getTotalFlags() {
		return totalFlags;
	}

	public void setTotalFlags(double totalFlags) {
		this.totalFlags = totalFlags;
	}
	
	public void cleanInformation()
	{
		synFlags = 0;
		synAckFlags = 0;
		finFlags = 0;
		totalFlags = 0;
	}

	//------------------------------------
	// Abstract Methods
	//------------------------------------
	
	/**
	 * Method that looks for an attacks using a desire algorithm
	 * @return The IP address of the server that's under attack
	 */
	public abstract String lookForAttack();
}
