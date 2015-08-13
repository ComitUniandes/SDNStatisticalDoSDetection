/**
 * Class that identifies if there-s and DDoS attack using a Chi-Sqaure Test
 * @author Laura Victoria Morales l.morales825@uniandes.edu.co
 */
package net.floodlightcontroller.DDoSFinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;

import net.floodlightcontroller.headerextract.ServerInfo;

public class ChiSquare implements IDDoSFinder
{
	/**
	 * ArrayList with auxiliar elements that represents the servers
	 */
	private ArrayList<ChiSquareAux> auxList;
	
	
	public ChiSquare()
	{
		auxList = new ArrayList<ChiSquareAux>();
		getServers();
	}

	@Override
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
					ChiSquareAux temp = new ChiSquareAux(line);
					auxList.add(temp);
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
	    	ServerInfo serverTemp = servers.get(i);
	    	ChiSquareAux auxTemp = lookForServer(serverTemp.getIp());
	    	auxTemp.addData(serverTemp.getSYNflags(), serverTemp.getSYNACKflags(), serverTemp.getRSTflags(), serverTemp.getFINflags(), serverTemp.getFINACKflags(),
	    			index);
		}
	}

	@Override
	public ChiSquareAux lookForServer(String ip) {
		for (int i = 0; i < auxList.size(); i++) 
		{
			ChiSquareAux temp = auxList.get(i);
			if(temp.getIp().equals(ip))
				return temp;
		}
		return null;
	}

	@Override
	public ArrayList<String> lookForAnAttack() {
		
		ArrayList<String> resp = new ArrayList<String>();
		for (int i = 0; i < auxList.size(); i++) 
		{
			ChiSquareAux temp = auxList.get(i);
			String aux = temp.lookForAttack();
			if(aux != null)
				resp.add(aux);
			temp.cleanInformation();
		}
		return resp;
	}

}
