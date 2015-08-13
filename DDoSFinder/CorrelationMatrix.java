/**
 * First Algorithm: Covariance Matrix
 * The Covariance Matrix implementation is from the Apache Commons project
 * @author Laura Victoria Morales l.morales825@uniandes.edu.co
 */

package net.floodlightcontroller.DDoSFinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;

import net.floodlightcontroller.headerextract.ServerInfo;

public class CorrelationMatrix implements IDDoSFinder
{
	//------------------------------------
	// Attributes
	//------------------------------------
	
	/**
	 * A list which contains the auxiliar classes 
	 */
	private ArrayList<CoMaAux> auxiliarList;
	
	
	//------------------------------------
	// Constructor
	//------------------------------------
	
	/**
	 * Creates an empty list and fills it with the information from the servers file
	 */
	public CorrelationMatrix()
	{
		auxiliarList = new ArrayList<CoMaAux>();
		getServers();
	}
	
	//------------------------------------
	// Methods
	//------------------------------------
	
	/**
	 * Creates the Auxiliar List with the servers IP
	 */
	public void getServers()
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
					CoMaAux temp = new CoMaAux(line);
					auxiliarList.add(temp);
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
	 * Receives the information and fills the server
	 * @param index - The Observation
	 * @param servers - The servers list with the information
	 */
	public void receiveInfo(int index, ArrayList<ServerInfo> servers)
	{
	    int realIndex = index-1;
	    for (int i = 0; i < servers.size(); i++) 
	    {
	    	ServerInfo serverTemp = servers.get(i);
	    	CoMaAux auxTemp = lookForServer(serverTemp.getIp());
	    	auxTemp.addData(serverTemp.getSYNflags(), serverTemp.getSYNACKflags(), serverTemp.getRSTflags(), serverTemp.getFINflags(), serverTemp.getFINACKflags(),
	    			realIndex);
		}
	}
	
	/**
	 * Search for the server in the list
	 */
	public CoMaAux lookForServer(String ip)
	{
		for (int i = 0; i < auxiliarList.size(); i++) 
		{
			CoMaAux temp = auxiliarList.get(i);
			if(temp.getIp().equals(ip))
				return temp;
		}
		return null;
	}
	
	/**
	 * Returns the list of servers under attack
	 * If there's no server under attack, then the list is an empty list
	 */
	public ArrayList<String> lookForAnAttack()
	{
		
		ArrayList<String> respList = new ArrayList<String>();
		for (int i = 0; i < auxiliarList.size(); i++) 
		{
			String toAdd = auxiliarList.get(i).lookForAttack();
			if(toAdd != null)
				respList.add(toAdd);
			auxiliarList.get(i).cleanInformation();
		}
		return respList;
	}
}
