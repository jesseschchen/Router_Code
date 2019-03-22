/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"
#include "core/protocol.hpp"

#include <string.h>
#include <fstream>

namespace simple_router {



void SimpleRouter::send_icmp_timeout(char* data, struct ip_hdr i_hdr, const std::string& inIface, uint8_t* src_mac, 
	uint32_t type)
{
	const Interface* iface = findIfaceByName(inIface);

	struct ethernet_hdr e_hdr;
	for(int i = 0; i < 6; i++)
	{
		e_hdr.ether_dhost[i] = src_mac[i];
		e_hdr.ether_shost[i] = iface->addr[i];
	}
	e_hdr.ether_type = htons(0x0800);

	struct ip_hdr new_hdr;
	new_hdr.ip_hl = 5;
	new_hdr.ip_v = 4;
	new_hdr.ip_tos = 0;
	new_hdr.ip_len = htons(new_hdr.ip_hl*4 + sizeof(icmp_hdr) + 4 + i_hdr.ip_hl*4 + 8);
	new_hdr.ip_id = htons(0);
	new_hdr.ip_off = htons(0);
	new_hdr.ip_ttl = 64;
	new_hdr.ip_p = 1;
	new_hdr.ip_dst = htonl(i_hdr.ip_src);
	new_hdr.ip_src = (type==11) ? iface->ip : htonl(i_hdr.ip_dst);
	new_hdr.ip_sum = 0; //compute_checksum((char*)&new_hdr, new_hdr);

	struct icmp_hdr icmp_out;
	icmp_out.icmp_type = type;
	icmp_out.icmp_code = (type==11) ? 0 : 3;
	icmp_out.icmp_sum = 0;

	i_hdr.ip_len = htons(i_hdr.ip_len);
	i_hdr.ip_id = htons(i_hdr.ip_id);
	i_hdr.ip_off = htons(i_hdr.ip_off);
	i_hdr.ip_sum = htons(i_hdr.ip_sum);
	i_hdr.ip_src = htonl(i_hdr.ip_src);
	i_hdr.ip_dst = htonl(i_hdr.ip_dst);

	uint32_t gap = 0;

	Buffer out_packet(sizeof(e_hdr) + i_hdr.ip_hl*4 + new_hdr.ip_hl*4 + sizeof(icmp_out) + 12);

	memcpy(out_packet.data(), &e_hdr, sizeof(e_hdr));
	memcpy(&out_packet.data()[14], &new_hdr, new_hdr.ip_hl * 4);
	memcpy(&out_packet.data()[14 + new_hdr.ip_hl*4], &icmp_out, sizeof(icmp_out));
	memcpy(&out_packet.data()[14 + new_hdr.ip_hl*4 + sizeof(icmp_out)], &gap, 4);
	memcpy(&out_packet.data()[14 + new_hdr.ip_hl*4 + sizeof(icmp_out) + 4], &i_hdr, i_hdr.ip_hl*4);
	memcpy(&out_packet.data()[14 + new_hdr.ip_hl*4 + sizeof(icmp_out) + 4 + i_hdr.ip_hl*4], &data[i_hdr.ip_hl*4], 8);


	new_hdr.ip_sum = compute_checksum((unsigned char*)&out_packet.data()[14], new_hdr);
	icmp_out.icmp_sum = compute_icmp_checksum((unsigned char*)&out_packet.data()[14 + new_hdr.ip_hl*4], 
		sizeof(icmp_out) + 4 + i_hdr.ip_hl*4 + 8);
	memcpy(&out_packet.data()[14], &new_hdr, new_hdr.ip_hl * 4);
	memcpy(&out_packet.data()[14 + new_hdr.ip_hl*4], &icmp_out, sizeof(icmp_out));

	std::cerr<<"TRACEROUTE\n";
	print_hdr_eth((const uint8_t*)out_packet.data());
	print_hdr_ip((const uint8_t*)&out_packet.data()[14]);
	std::cerr<<"ip checksum: " <<new_hdr.ip_sum << "\n";
	std::cerr<<"IP checksum check: "<<cksum(&out_packet.data()[14], new_hdr.ip_hl*4) << "\n";
	print_hdr_icmp((const uint8_t*)&out_packet.data()[14 + new_hdr.ip_hl*4]);
	print_hdr_ip((const uint8_t*)&out_packet.data()[14 + new_hdr.ip_hl*4 + sizeof(icmp_out) + 4]);

	std::cerr<<inIface<<"\n";

	sendPacket(out_packet, inIface);
}

Buffer SimpleRouter::send_request(uint32_t dst_ip, Interface* iface)
{	
	std::cerr<<"send request\n";
	struct ethernet_hdr out_hdr; //network
	out_hdr.ether_type = htons(0x0806);
	for(int j = 0; j < ETHER_ADDR_LEN; j++)
	{
		out_hdr.ether_dhost[j] = 0xff;
		out_hdr.ether_shost[j] = iface->addr[j];
	}

	struct arp_hdr arp_request;
	arp_request.arp_hrd = htons(1);
	arp_request.arp_pro = htons(0x0800);
	arp_request.arp_hln = 6;
	arp_request.arp_pln = 4;
	arp_request.arp_op = htons(1);
	arp_request.arp_tip = dst_ip;
	arp_request.arp_sip = iface->ip;
	for(int i = 0; i < ETHER_ADDR_LEN; i++)
	{
		arp_request.arp_sha[i] = iface->addr[i];
		arp_request.arp_tha[i] = 0xff;
	}

	Buffer out_packet(sizeof(arp_request) + sizeof(out_hdr));
	memcpy(&out_packet.data()[14], &arp_request, sizeof(arp_request));
	memcpy(out_packet.data(), &out_hdr, sizeof(out_hdr));
	//std::cerr<<"arp_ether:\n";
	print_hdr_eth((const uint8_t*)out_packet.data());
	//std::cerr<<"arp_hdr:\n";
	print_hdr_arp((const uint8_t*)&out_packet.data()[14]);

	sendPacket(out_packet, iface->name);

	return out_packet;
}

uint16_t SimpleRouter::compute_icmp_checksum(unsigned char* data, int length)
{

	uint32_t temp = 0;
	for(int i = 0; i < length - length % 2; i += 2)
	{
		if(i != 2)
			temp += (data[i] << 8) + data[i+1];
	}
	if(length % 2 == 1)
	{
		temp += data[length - 1] << 8;
	}
	while(temp > 65535)
	{
		temp = (temp>>16) + (temp & 65535);
	}
	uint16_t final = htons(~((uint16_t)temp));
	return final ? final : 0xffff;
}

uint16_t SimpleRouter::compute_checksum(unsigned char* data, struct ip_hdr i_hdr)
{
	uint32_t temp = 0;

	for(int i = 0; i < i_hdr.ip_hl*4; i += 2)
	{
		if(i != 10)
		{
			temp += (data[i] << 8 ) + data[i+1];
			//std::cerr<<"temp += "<<(data[i] << 8 ) + data[i+1]<<"\n";
		}
		
	}
	while(temp > 65535)
	{
		temp = (temp >> 16) + (temp & 65535);
	}
	uint16_t final = htons(~temp);
	return final ? final : 0xffff;
}

void SimpleRouter::forward_datagram(char* whole_pack, struct ip_hdr i_hdr, int length, const Interface* iface, uint8_t* src_mac)
{
	std::cerr<<"forward begin\n";
	if(i_hdr.ip_ttl <= 1)
	{
		std::cerr<<"prep timeout\n";
		send_icmp_timeout(whole_pack, i_hdr, iface->name, src_mac, 11);
		std::cerr<<"sent timeout\n";
		return;
	}
	i_hdr.ip_ttl -= 1; //decrement ttl by one
	whole_pack[8] = i_hdr.ip_ttl;
	i_hdr.ip_sum = compute_checksum((unsigned char*)whole_pack, i_hdr); //modify ipv4 checksum


	RoutingTableEntry next_hop = m_routingTable.lookup(htonl(i_hdr.ip_dst)); //get gateway ip address
	uint32_t dest_gw = next_hop.gw;
	Interface* gw_iface = (Interface*)findIfaceByName(next_hop.ifName); //gateway interface

	std::shared_ptr<ArpEntry> arp_lookup = m_arp.lookup(dest_gw); //get gateway mac address
	bool in_cache = (arp_lookup == nullptr) ? 0 : 1;

	struct ethernet_hdr out_hdr;
	out_hdr.ether_type = htons(0x0800);
	for(int j = 0; j < ETHER_ADDR_LEN; j++)
	{
		out_hdr.ether_dhost[j] = in_cache ? arp_lookup->mac[j] : 0;
		out_hdr.ether_shost[j] = gw_iface->addr[j];
	}

	i_hdr.ip_len = htons(i_hdr.ip_len);
	i_hdr.ip_id = htons(i_hdr.ip_id);
	i_hdr.ip_off = htons(i_hdr.ip_off);
	i_hdr.ip_sum = i_hdr.ip_sum;
	i_hdr.ip_src = htonl(i_hdr.ip_src);
	i_hdr.ip_dst = htonl(i_hdr.ip_dst);



	Buffer out_packet(sizeof(out_hdr) + ntohs(i_hdr.ip_len));
	memcpy(out_packet.data(), &out_hdr, sizeof(out_hdr));
	memcpy(&out_packet.data()[14], &i_hdr, i_hdr.ip_hl*4);
	memcpy(&out_packet.data()[14 + i_hdr.ip_hl*4], &whole_pack[i_hdr.ip_hl*4], ntohs(i_hdr.ip_len) - i_hdr.ip_hl*4);

	std::cerr<<"forwarded:\n";
	print_hdr_eth((const uint8_t*)out_packet.data());
	print_hdr_ip((const uint8_t*)&out_packet.data()[14]);
	//print_hdr_ip((const uint8_t*)whole_pack);
	print_hdr_icmp((const uint8_t*)&out_packet.data()[14 + i_hdr.ip_hl*4]);

	//std::cerr<<"ip checksum: " <<i_hdr.ip_sum << "\n";
	//std::cerr<<"IP checksum check: "<<cksum(&out_packet.data()[14], i_hdr.ip_hl*4) << "\n";



	if(arp_lookup == nullptr)//not in ARP cache
	{
		send_request(dest_gw, gw_iface);
		m_arp.queueRequest(dest_gw, out_packet, next_hop.ifName);
		std::cerr<<"sent arp request\n";
	}
	else //found in ARP cache
	{
		sendPacket(out_packet, next_hop.ifName);
		std::cerr<<next_hop.ifName<<"\n";
		std::cerr<<"forwarded packet\n";
	}
	//free(arp_lookup);
}

void SimpleRouter::handle_ICMP(char* data, struct ip_hdr i_hdr, int length, const std::string& inIface, uint8_t* src_mac)
{
	struct icmp_hdr icmp; //host
	icmp.icmp_type = data[0];
	icmp.icmp_code = data[1];
	icmp.icmp_sum = ntohs(((short*)data)[1]);
	print_hdr_icmp((const uint8_t*)&icmp);
	std::cerr<<"checksum: "<< cksum(data, length)<<"\n";
	if(icmp.icmp_type == 8 && cksum(data, length) == 0xffff) //echo request with valid checksum
	{
		//const Interface* iface = findIfaceByName(inIface);

		RoutingTableEntry reply_hop = m_routingTable.lookup(htonl(i_hdr.ip_src)); //get gateway ip address
		uint32_t dest_gw = reply_hop.gw;
		Interface* gw_iface = (Interface*)findIfaceByName(reply_hop.ifName); //gateway interface

		std::shared_ptr<ArpEntry> arp_lookup = m_arp.lookup(dest_gw); //get gateway mac address
		bool in_cache = (arp_lookup == nullptr) ? 0 : 1;


		struct ethernet_hdr e_hdr; //network
		for(int i = 0; i < 6; i++)
		{
			e_hdr.ether_dhost[i] = in_cache ? arp_lookup->mac[i] : 0;
			e_hdr.ether_shost[i] = gw_iface->addr[i];
		}
		e_hdr.ether_type = htons(0x0800);

		struct ip_hdr new_hdr; //network
		new_hdr.ip_hl = 5;
		new_hdr.ip_v = 4;
		new_hdr.ip_tos = 0;
		new_hdr.ip_len = htons(new_hdr.ip_hl*4 + length);
		new_hdr.ip_id = htons(0);
		new_hdr.ip_off = htons(0);
		new_hdr.ip_ttl = 64;
		new_hdr.ip_p = 1;
		new_hdr.ip_dst = htonl(i_hdr.ip_src);
		new_hdr.ip_src = htonl(i_hdr.ip_dst);
		new_hdr.ip_sum = htons(12345); //compute_checksum((char*)&new_hdr, new_hdr);

		struct icmp_hdr reply; //network
		reply.icmp_type = 0;
		reply.icmp_code = 0;
		reply.icmp_sum = 0; //compute_icmp_checksum(data, length); 
		

		Buffer out_packet(sizeof(e_hdr) + new_hdr.ip_hl*4 + length);
		memcpy(out_packet.data(), &e_hdr, sizeof(e_hdr));
		memcpy(&out_packet.data()[14], &new_hdr, new_hdr.ip_hl*4);
		memcpy(&out_packet.data()[14 + new_hdr.ip_hl*4], &reply, sizeof(reply));
		memcpy(&out_packet.data()[14 + new_hdr.ip_hl*4 + sizeof(reply)], &data[sizeof(reply)], length - sizeof(reply));

		new_hdr.ip_sum = compute_checksum((unsigned char*)&out_packet.data()[sizeof(e_hdr)], new_hdr);
		memcpy(&out_packet.data()[14], &new_hdr, new_hdr.ip_hl*4);
		std::cerr<<"ip checksum: " <<new_hdr.ip_sum << "\n";
		std::cerr<<"IP checksum check: "<<cksum(&out_packet.data()[sizeof(e_hdr)], new_hdr.ip_hl*4) << "\n";

		reply.icmp_sum = compute_icmp_checksum((unsigned char*)&out_packet.data()[14 + new_hdr.ip_hl*4], length);
		memcpy(&out_packet.data()[14 + new_hdr.ip_hl*4], &reply, sizeof(reply));
		std::cerr<<"icmp_checksum: "<<reply.icmp_sum<<"\n";
		std::cerr<<"icmp_checksum_check: "<<cksum(&out_packet.data()[14 + new_hdr.ip_hl*4], length)<<"\n";

		std::cerr<<"ethernet_out:\n";
		print_hdr_eth(out_packet.data());

		std::cerr<<"ip_out:\n";
		print_hdr_ip((const uint8_t*)&out_packet.data()[14]);

		std::cerr<<"icmp out\n";
		print_hdr_icmp((const uint8_t*)&out_packet.data()[14 + new_hdr.ip_hl*4]);


		if(arp_lookup == nullptr)//not in ARP cache
		{
			send_request(dest_gw, gw_iface);
			m_arp.queueRequest(dest_gw, out_packet, reply_hop.ifName);
			std::cerr<<"sent ICMP arp request\n";
		}
		else //found in ARP cache
		{
			sendPacket(out_packet, reply_hop.ifName);
		}
		//free(arp_lookup);
	}
}

void SimpleRouter::handle_ARP(char* data, int length, uint32_t thi_ip, Buffer thi_mac, const std::string& inIface)
{
	struct arp_hdr a_hdr; //host
	a_hdr.arp_hrd = ntohs(((short*)data)[0]);
	a_hdr.arp_pro = ntohs(((short*)data)[1]);
	a_hdr.arp_hln = data[4];
	a_hdr.arp_pln = data[5];
	a_hdr.arp_op = ntohs(((short*)data)[3]);
	for(int i = 0; i < ETHER_ADDR_LEN; i++)
	{
		a_hdr.arp_sha[i] = data[8 + i];
		a_hdr.arp_tha[i] = data[8 + a_hdr.arp_hln + a_hdr.arp_pln + i];
	}
	a_hdr.arp_sip = ntohl(((uint32_t*)&data[14])[0]);
	a_hdr.arp_tip = ntohl(((uint32_t*)&data[24])[0]);

	if(a_hdr.arp_hrd != 1 || a_hdr.arp_pro != 0x0800 || a_hdr.arp_hln != 6 || a_hdr.arp_pln != 4)
	{
		//invalid arp packet
		std::cerr<<"invalid arp packet headers\n";
		return;
	}


	//std::cerr<<"arp_op = "<<a_hdr.arp_op<<"\n";
	print_hdr_arp((const uint8_t*)data);

	if(a_hdr.arp_op == 1) //ARP request
	{
		if(thi_ip == a_hdr.arp_tip) //ip match
		{
			std::cerr<<"arp request\n";
			struct ethernet_hdr out_hdr; //network
			for(int j = 0; j < ETHER_ADDR_LEN; j++)
			{
				out_hdr.ether_dhost[j] = a_hdr.arp_sha[j];
				out_hdr.ether_shost[j] = thi_mac[j];
			}
			out_hdr.ether_type = htons(0x0806);

			struct arp_hdr arp_reply; //network
			arp_reply.arp_hrd = htons(1);
			arp_reply.arp_pro = htons(0x0800);
			arp_reply.arp_hln = 6;
			arp_reply.arp_pln = 4;
			arp_reply.arp_op = htons(2);
			for(int i = 0; i < ETHER_ADDR_LEN; i++)
			{
				arp_reply.arp_sha[i] = thi_mac[i];
				arp_reply.arp_tha[i] = a_hdr.arp_sha[i];
			}
			arp_reply.arp_sip = htonl(thi_ip);
			arp_reply.arp_tip = htonl(a_hdr.arp_sip);
			Buffer out_packet(sizeof(arp_reply) + sizeof(out_hdr));
			memcpy(out_packet.data(), &out_hdr, sizeof(out_hdr));		
			memcpy(&out_packet.data()[14], &arp_reply, sizeof(arp_reply));

			sendPacket(out_packet, inIface);

			//m_arp.queueRequest(thi_ip, out_packet, inIface);
		}
	}
	else if(a_hdr.arp_op == 2) //ARP reply
	{
		std::cerr<<"recv arp reply\n";
		//record mappings
		Buffer mac;
		for(int i = 0; i < a_hdr.arp_hln; i++)
		{
			mac.push_back(a_hdr.arp_sha[i]);
		}
		

		std::shared_ptr<ArpEntry> dup = m_arp.lookup(htonl(a_hdr.arp_sip));
		std::shared_ptr<ArpRequest> comp_req = nullptr;
		if(dup == nullptr) //not in the arp cache already
		{
			comp_req = m_arp.insertArpEntry(mac, htonl(a_hdr.arp_sip));
			std::cerr<<"new cache entry: "<<macToString(mac)<< " <--> " << ipToString(htonl(a_hdr.arp_sip)) << "\n";
		}
		m_arp.print();


		struct ethernet_hdr fixed_hdr; //network
		for(int i = 0; i < ETHER_ADDR_LEN; i++)
		{
			fixed_hdr.ether_dhost[i] = mac[i];
			fixed_hdr.ether_shost[i] = thi_mac[i];
		}
		fixed_hdr.ether_type = htons(0x0800);
		std::cerr<<"queued:\n";
		print_hdr_eth((const uint8_t*)&fixed_hdr);


		//send out queued packets
		if(comp_req != nullptr) //valid request
		{
			std::cerr<<"successful arp reply\n";
			std::list<PendingPacket> packet_queue = comp_req->packets;
			for(const auto& entry : packet_queue)
			{
				memcpy((void*)entry.packet.data(), &fixed_hdr, sizeof(fixed_hdr));
				sendPacket(entry.packet, entry.iface);
				std::cerr<<"iface: "<<entry.iface<<"\n";
				//print_hdr_eth((const uint8_t*)entry.packet.data());
				//print_hdr_ip((const uint8_t*)&entry.packet.data()[14]);

				//struct ip_hdr* i_hdr = (struct ip_hdr*)&entry.packet.data()[14];

				//std::cerr<<"ip checksum: " <<i_hdr->ip_sum << "\n";
				//std::cerr<<"IP checksum check: "<<cksum(i_hdr, i_hdr->ip_hl*4) << "\n";
			}
			m_arp.removeRequest(comp_req); ///IS THIS WORKING
		}
		//free(dup);
	}
}

void SimpleRouter::handle_IPV4(char* data, int length, uint32_t thi_ip, Buffer thi_mac, const std::string& inIface, 
	uint8_t* src_mac)
{
	struct ip_hdr i_hdr; //host
	i_hdr.ip_hl = (data[0] & 15); //header is in words, 
	i_hdr.ip_v = (data[0] >> 4);
	i_hdr.ip_tos = data[1];
	i_hdr.ip_len = ntohs(((short*)data)[1]);
	i_hdr.ip_id = ntohs(((short*)data)[2]);
	i_hdr.ip_off = ntohs(((short*)data)[3]);
	i_hdr.ip_ttl = data[8];
	i_hdr.ip_p = data[9];
	i_hdr.ip_sum = ntohs(((short*)data)[5]);
	i_hdr.ip_src = ntohl(((int*)data)[3]);
	i_hdr.ip_dst = ntohl(((int*)data)[4]);


	//verify checksum
	std::cerr<<ipToString(htonl(thi_ip))<<"\n";
	print_hdr_ip((const uint8_t*)data);

	if(cksum(data, i_hdr.ip_hl * 4) != 0xffff || length < 20)//invalid checksum
	{
		std::cerr<<"cksum: "<<cksum(data, i_hdr.ip_hl*4)<<"\n";
		std::cerr<<"invalid checksum\n";
		return;
	}


	const Interface* ip_Iface = findIfaceByIp(htonl(i_hdr.ip_dst)); 
	if(ip_Iface == nullptr) //not to this router
	{
		forward_datagram(data, i_hdr, length, (Interface*)findIfaceByName(inIface), src_mac);
		//datagram is to be forwarded
		//forward_datagram() maybe
		//if found in arp-cache
			//send it out
		//else send arp_request
	}
	else if(i_hdr.ip_p == 1)//this packet is meant for this router and is icmp packet
	{
		std::cerr<<"handle icmp\n";
		handle_ICMP(&data[i_hdr.ip_hl*4], i_hdr, i_hdr.ip_len - i_hdr.ip_hl*4, inIface, src_mac);
	}
	else if(i_hdr.ip_p == 6 || i_hdr.ip_p == 17) //tcp or udp packet
	{
		std::cerr<<"protocol == "<<(int)i_hdr.ip_p<<"\n";
		send_icmp_timeout(data, i_hdr, inIface, src_mac, 3);
	}
}


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "\nGot packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  print_hdr_eth((const uint8_t*)packet.data());

  struct ethernet_hdr hdr;
  for(int i = 0; i < ETHER_ADDR_LEN; i++)
  {
  		hdr.ether_dhost[i] = packet[i];
  		hdr.ether_shost[i] = packet[i+6];
  }
  hdr.ether_type = ntohs(*(uint16_t*)&packet[12]);

  uint8_t* broadcast = (uint8_t*)malloc(6);
  for(int i = 0; i < 6; i++)
  {
  	broadcast[i] = 0xff;
  }


  	if(macToString(iface->addr) != macToString(packet) && macToString(packet) != "ff:ff:ff:ff:ff:ff")
  	{
  		return;
  	}

	if(hdr.ether_type == 2054)
	{
		std::cerr<<"handle arp\n";
		//ARP packets packet[14]
		handle_ARP((char*)&packet[14], packet.size()-14, ntohl(iface->ip), iface->addr, inIface);
	}
	else if(hdr.ether_type == 2048)
	{
		//IPV4 packets
		std::cerr<<"handle ipv4\n";
		handle_IPV4((char*)&packet[14], packet.size()-14, ntohl(iface->ip), iface->addr, inIface, hdr.ether_shost);
	}
	else
	{
		std::cerr << "invalid payload type " << hdr.ether_type << std::endl;
	}
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
