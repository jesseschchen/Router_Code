Jesse Chen
204-578-044
CS118
project 3: Riddikulus

HIGH LEVEL DESIGN PSEUDOCODE:
	simple-router.cpp:
		handlePacket()
		{
			if(is_arp_packet)
				handle_arp();
			else if(is_ipv4_packet)
				handle_ipv4();
			else
				ignore_packet();
		}

		handle_arp()
		{
			if(is_arp_reply)
				add_new_arp_entry();
			else if(is_arp_request)
				send_arp_reply();
			else
				ignore_packet();
		}

		handle_ipv4()
		{
			if(dest_ip != router_ip)
				forward_packet();
			else if(dest_ip == router_ip && is_icmp_packet)
				handle_icmp();
			else if(udp_or_tcp_packet)
				send_icmp_type3();
		}

		handle_icmp()
		{
			if(echo_request_packet)
				send_echo_reply();
		}

	arp-cache.cpp:
		periodicCheckArpRequestsAndCacheEntries()
		{
			for(entry in cacheEntries)
			{
				if(!entry.isValid)
					remove(entry);
			}
			for(req in arpRequests)
			{
				if(req.timesSent >= 5)
					remove(req);
				else
					send_request(req);
					update(req);
			}
		}

	routing-table.cpp:
		lookup(ip)
		{
			for(entry in tableEntries)
			{
				if(entry.subnet == ip.subnet)
					if(subnet_mask > prev_largest_subnet_mask)
						set_new_return_entry;
			}
			return return_entry;
		}

ENCOUTERED DIFFICULTIES: 
	1. multiple router interfaces:
		Multiple router interfaces meant that sometimes a packet that arrived on interface A 
		might be destined to interface B's ip address. Also, care must be taken to ensure that 
		outgoing packets are sent out of the correct interface with the correct headers.  For 
		example, if the router receives a ping request on interface A for interface B's ip address, 
		the ping response's source ip will not be the ip address of the interace that it exits out of.  

ADDITIONAL LIBRARIES USED:
	All libraries used were already included in the skeleton code. 


OTHER ACKNOWLEDGMENTS:
	1. Linux man pages: man7.org, linux.die.net
	2. Online man pages/code example: tutorialspoint.com
	3. Online man pages/code exmaple: cplusplus.com
	4. ICMP/ARP header information: networksorcery.com



