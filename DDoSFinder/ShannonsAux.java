/**
 * Auxiliar class for Shannon's Entropy Alg.
 * This class will perform Shannon's entropy to a server
 * @author Laura Victoria Morales l.morales825@uniandes.edu.co
 */

package net.floodlightcontroller.DDoSFinder;

public class ShannonsAux extends AuxiliarClass
{	
	//------------------------------------
	// Attributes
	//------------------------------------
	
	/**
	 * Shannon's Entropy
	 */
	private double shannons;
	
	//------------------------------------
	// Constructor
	//------------------------------------
	
	/**
	 * Creates a new ShannonsAux Class
	 * It will use the AuxiliarClass to initialize the flags counts, server Ip, and list of IPs
	 * @param serversIp / The server's IP
	 */
	public ShannonsAux(String serversIp)
	{
		super(serversIp);
		shannons = 0;
	}

	//------------------------------------
	// Methods
	//------------------------------------

	/**
	 * Get the Shannon's value
	 * @return Channon's value
	 */
	public double getShannons() 
	{
		return shannons;
	}

	/**
	 * (Implements Auxiliar Class Method)
	 * Looks for an attack using Shannon's Entropy Method
	 * It will calculate Shannon's Entropy for the three flags: Syn, Syn-Ack and Fin
	 * @return This - If Shannon's entropy is lower than the threshold (1.3)
	 *         Null - If Shannon's entropy is higher than the threshold
	 */
	@Override
	public String lookForAttack() {
		double probSyn = super.getSynFlags()/super.getTotalFlags();
		double probSynAck = super.getSynAckFlags()/super.getTotalFlags();
		double probFin = super.getFinFlags()/super.getTotalFlags();
		double p1 = 0;
		double p2 = 0;
		double p3 = 0;
		
		if(probSyn != 0)
			p1 = probSyn*(Math.log(probSyn)/Math.log(2));
		if(probSynAck != 0)
			p2 = probSynAck*(Math.log(probSynAck)/Math.log(2));
		if(probFin != 0)	
			p3 = probFin*(Math.log(probFin)/Math.log(2));
				
		shannons = -(p1+p2+p3);
		
		System.out.println("[SHANNON'S ENTROPY] Server: "+super.getIp()+"\n " +
				"Entropy: "+shannons);
		
		super.setSynFlags(0);
		super.setSynAckFlags(0);
		super.setFinFlags(0);
		super.setTotalFlags(0);
		
		if(shannons<1.3)
			return this.getIp();
		else
			return null;
	}

	
}
