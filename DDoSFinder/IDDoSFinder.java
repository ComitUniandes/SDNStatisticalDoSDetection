/**
 * Interface that characterize a DDoS FInder algorithm
 * @author Laura Victoria Morales l.morales825@uniandes.edu.co
 */

package net.floodlightcontroller.DDoSFinder;

import java.util.ArrayList;

import net.floodlightcontroller.headerextract.ServerInfo;

public interface IDDoSFinder 
{
	/**
	 * Reads the server list and creates the auxiliar list from that file.
	 * Each IP represents a new object on the list
	 */
	public void getServers();
	
	/**
	 * Receives the info neccesary to detect the attack
	 * @param index - The i-th observation
	 * @param servers - List of the hosts that are requesting
	 */
	public void receiveInfo(int index, ArrayList<ServerInfo> servers);
	
	/**
	 * Looks for a server that has the IP passed as a parameter
	 * @param ip - The IP of the server we're looking for
	 * @return The Server we're looking for, null if it doesn't exist (This should never happen)
	 */
	public AuxiliarClass lookForServer(String ip);
	
	/**
	 * Looks for an DDoS attack on the server list
	 * @return The list with all the servers' IP addresses that are under attack
	 */
	public ArrayList<String> lookForAnAttack();

}
