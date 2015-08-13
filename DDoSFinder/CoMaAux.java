/**
 * Auxiliar Class. It will contain the matrix for each server
 * @author Laura Victoria Morales Medina l.morales825@uniandes.edu.co
 */
package net.floodlightcontroller.DDoSFinder;

import org.apache.commons.math3.linear.RealMatrix;
import org.apache.commons.math3.stat.correlation.Covariance;
import org.apache.commons.math3.stat.correlation.PearsonsCorrelation;

public class CoMaAux extends AuxiliarClass
{	
	//------------------------------------
	// Attributes
	//------------------------------------
	
    /**
     * The Matrix that will represent the flags data
     */
	private double[][] data;
	
	/**
	 * The Covariance Matrix.
	 */
	private Covariance matrix;
	
	/**
	 * The Correlation Matrix
	 */
	private PearsonsCorrelation matrix2;
	
	//------------------------------------
	// Constructor
	//------------------------------------
	
	/**
	 * Creates a new data Matrix with 5 rows and 4 columns
	 * It uses Auxiliar Class constructor to create the flags 
	 * @param serverIp - The servers IP
	 */
	public CoMaAux(String serverIp)
	{
		super(serverIp);
		data = new double[4][4]; //The Matrix will always have 5 rows and 4 columns
	}
	
	//------------------------------------
	// Methods
	//------------------------------------
	
	/**
	 * Adds the data to the matrix
	 * @param syn
	 * @param synAck
	 * @param rst
	 * @param fin
	 * @param finAck
	 * @param index
	 */
	public void addData(int syn, int synAck, int rst, int fin, int finAck, int index)
	{
		int third = fin+finAck;
		data[index][0] = syn;
		data[index][1] = synAck;
		data[index][2] = third;
		data[index][3] = rst;
	}
	
	/**
	 * Checks if this server is under an attack
	 * @return This, if this server is under attack or null if is not
	 */
	public String lookForAttack()
	{
		matrix = new Covariance(data);
		matrix2 = new PearsonsCorrelation(matrix);
		RealMatrix realM = matrix2.getCorrelationMatrix();
		double [][] data = realM.getData();
		String resp = "";
		for (int i = 0; i < realM.getRowDimension(); i++) 
		{
			resp += "\n";
			for (int j = 0; j < realM.getColumnDimension(); j++) 
			{
				resp += data[i][j]+" ";
			}
		}
		System.out.println("[DETECTING AN ATTACK] Server: "+super.getIp()+" \n"
				+"Matrix: \n"+resp);
		if(data[1][0] < 0.7)
			return this.getIp();
		else if(data[2][0] < 0.7)
			return this.getIp();
		else if(data[2][1] < 0.7)
			return this.getIp();
		else if(data[3][0] > 0.3 || data[3][1] > 0.3)  //If there's a lot of RST flags, then the correlation between this and SYN flags will raise
			return this.getIp();
		
		return null;
	}
	
	public void cleanInformation()
	{
		super.cleanInformation();
		data = new double[5][4];
	}

	public double[][] getData() {
		return data;
	}

}
