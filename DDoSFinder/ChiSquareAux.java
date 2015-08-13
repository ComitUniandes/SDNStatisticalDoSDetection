package net.floodlightcontroller.DDoSFinder;

import org.apache.commons.math3.distribution.ChiSquaredDistribution;

public class ChiSquareAux extends AuxiliarClass
{
	//------------------------------------
	// Attributes
	//------------------------------------
	
	/**
	 * Alpha value
	 */
	private static double ALPHA = 0.05;
	
	/**
	 * Expected probability
	 */
	private double expectedProb;
	
	/**
	 * ChiSquare Distribution table
	 */
	private ChiSquaredDistribution chiSquare;
	
	/**
	 * Degrees of freedom
	 */
	private final static int DEGREES = 2; //Since there are 3 observations: SYN, SYN-ACK and FIN flags. Then, the degrees of freedom is always 2
	
	//------------------------------------
	// Constructor
	//------------------------------------
	
	/**
	 * Creates a new auxiliar class.
	 * @param ip - The server Ip
	 */
	public ChiSquareAux(String ip)
	{
		super(ip);
		this.expectedProb = 1.0/3.0;
	}

	/**
	 * Returns the ChiSuqare value
	 * @return
	 */
	public ChiSquaredDistribution getChiSquare() 
	{
		return chiSquare;
	}

	@Override
	public String lookForAttack() {
		
		
		
		double finalProb = 0;
		
		double expected = expectedProb*super.getTotalFlags();
		System.out.println("[CHI_SQUARE] Total FinFlags: "+super.getFinFlags() +
				"\n Total SYN Flags: "+super.getSynFlags() +
				"\n Total SYN-ACK Flags: "+super.getSynAckFlags()
				+ "\n Total Flags: "+super.getTotalFlags()
				+ "\n expected: "+expected);
		
		
		if(super.getFinFlags() == expected && super.getSynFlags() == expectedProb && super.getSynAckFlags() == expectedProb)
			finalProb = 0;
		else
		{
			double p1 = Math.pow((super.getSynFlags()-expected), 2)/expected;
			double p2 = Math.pow((super.getSynAckFlags()-expected), 2)/expected;
			double p3 = Math.pow((super.getFinFlags()-expected), 2)/expected;
			
			finalProb = (p1+p2+p3);
		}		
		chiSquare = new ChiSquaredDistribution(DEGREES);
		System.out.println("[CHI_SQUARE] final Prob: "+finalProb);
		double resp = 1 - chiSquare.cumulativeProbability(finalProb);
		System.out.println("[CHI_SQUARE] Chi_Square value: "+resp);
		
	    if(resp < ALPHA)
	    	return this.getIp();
	    else
	    	return null;

	}
	
	
	
	

}
