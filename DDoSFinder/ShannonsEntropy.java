/**
 * Second Algorithm: Shannon's Entropy
 * It will look for the randomness in the TCP flags
 * @author Laura Victoria Morales l.morales825@uniandes.edu.co
 */
package net.floodlightcontroller.DDoSFinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;

import net.floodlightcontroller.headerextract.ServerInfo;

public class ShannonsEntropy implements IDDoSFinder
{
	//------------------------------------
	// Attributes
	//------------------------------------
	
	/**
	 * List that contains the auxiliar list with the servers
	 */
	private ArrayList<ShannonsAux> auxiliarList;
	
	
	//------------------------------------
	// Constructor
	//------------------------------------
	
	/**
	 * Initializes the auxiliar List as an empty list
	 * Reads the server list to create the auxiliar list
	 */
	public ShannonsEntropy()
	{
		auxiliarList = new ArrayList<ShannonsAux>();
		getServers();
	}
	
	//------------------------------------
	// Methods
	//------------------------------------
	
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
					ShannonsAux temp = new ShannonsAux(line);
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

	@Override
	public void receiveInfo(int index, ArrayList<ServerInfo> servers) 
	{
		for (int i = 0; i < servers.size(); i++) 
		{
			ServerInfo temp1 = servers.get(i);
			ShannonsAux temp2 = (ShannonsAux)lookForServer(temp1.getIp());
			temp2.addData(temp1.getSYNflags(), temp1.getSYNACKflags(),temp1.getRSTflags(), temp1.getFINflags(), temp1.getFINACKflags(), index);
		}		
	}

	@Override
	public AuxiliarClass lookForServer(String ip) 
	{
		for (int i = 0; i < auxiliarList.size(); i++)
		{
			ShannonsAux temp = auxiliarList.get(i);
			if(temp.getIp().equals(ip))
				return temp;
		}
		return null;
	}

	@Override
	public ArrayList<String> lookForAnAttack() 
	{
		ArrayList<String> resp = new ArrayList<String>();
		for (int i = 0; i < auxiliarList.size(); i++) 
		{
			ShannonsAux temp = auxiliarList.get(i);
			String aux = temp.lookForAttack();
			if(aux != null)
				resp.add(aux);
			temp.cleanInformation();
		}
		return resp;
	}

}
