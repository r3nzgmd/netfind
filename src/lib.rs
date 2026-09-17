use std::net::{IpAddr, Ipv4Addr};
use ipnetwork::Ipv4Network;
use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

// NOTE: using this library requires to run the program with SUDO - sending ARP packets requires
// superuser privileges
// scan() returns Option<Vec<>> of devices found in LAN network
// list() shows a list of devices on screen

pub struct Device {
    pub address: Ipv4Addr,
    pub mac: MacAddr,
}

pub fn scan() -> Option<Vec<Device>> {
    let mut possible_addresses = Vec::new();

    for iface in get_interfaces() {
        // opening (tx, rx) channels for sending ARP replies
        let channel_config = datalink::Config {
            read_timeout: Some(std::time::Duration::from_secs(3)),
            write_timeout: Some(std::time::Duration::from_secs(3)),
            ..Default::default()
        };
        let (mut tx, rx) = match datalink::channel(&iface, channel_config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => panic!("Error creating raw socket. Try running this program with sudo."),
        };

        // opening a listener on a different, non-blocking thread
        let handle = std::thread::spawn(move || {
            let mut hosts_found: Vec<Device> = Vec::new();
            check_packets(rx, &mut hosts_found);
            hosts_found
        });

        // getting current interface IP address and MAC address
        let source_mac = iface.mac.expect("MAC address not found.");
        let source_ip = iface.ips.iter()
            .find_map(|ip| {
                if let IpAddr::V4(ipv4) = ip.ip() {
                    Some(ipv4)
                } else {
                    None
                }
            }).expect("Interface does not have a valid IPv4 address.");

        // creating a list of all IPs in an interface to find all possible IPs
        for ip in iface.ips {
            if let IpAddr::V4(ipv4) = ip.ip() {
                let network = Ipv4Network::new(ipv4, ip.prefix()).expect("Invalid IPv4 address.");
                possible_addresses.push(find_addresses(network));
            }
        }

        // sending ARP requests to networks
        for address in &possible_addresses {
            for target_ip in address {
                let packet = create_arp_request(source_mac, source_ip, *target_ip);
                tx.send_to(&packet, None);
            }
        }

        // returning vector of found hosts from a different thread
        match handle.join() {
            Ok(hosts_found) => {
                return Some(hosts_found);
            },
            Err(_) => panic!("Error: couldn't create list of IP addresses."),
        }
    }
    None
}

// optional function to print all found hosts
pub fn list() {
    println!("Scanning networks...");
    let found_hosts = scan();

    println!(" ------------------------------------------------------- ");
    println!("| Index        IP address             MAC address       |");

    if let Some(list) = found_hosts {
        for (index, host) in list.iter().enumerate() {
            println!("|   {:<8.8}  {:<15.15}     {}     |", format!("{}.", index), host.address.to_string() ,host.mac.to_string());
        }
    }

    println!(" ------------------------------------------------------- ");
}

// finds every IP address in a network and returns vector of all addresses
fn find_addresses(network: Ipv4Network) -> Vec<Ipv4Addr> {
    let mut addresses = vec![Ipv4Addr::UNSPECIFIED; network.size() as usize];

    // finding network IP and broadcast IP
    let start = u32::from(network.network());
    let end = u32::from(network.broadcast());

    // saving possible IP addresses
    for (index, ip) in (start..=end).enumerate() {
        addresses[index] = Ipv4Addr::from(ip);
    }

    addresses
}

// creates an ARP request and returns it as raw bytes
fn create_arp_request(source_mac: MacAddr, source_ip: Ipv4Addr, target_ip: Ipv4Addr) -> [u8; 42] {
    let mut buffer = [0u8; 42];
    let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();

    // filling packet's header
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(source_mac);
    eth_packet.set_ethertype(EtherTypes::Arp);

    // ARP packet
    let mut arp_packet = MutableArpPacket::new(eth_packet.payload_mut()).unwrap();

    // filling hardware information
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);

    // filling IP addresses
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    // returning raw bytes of the ARP request
    buffer
}

// helper function to get only working interfaces
fn get_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();

    for iface in datalink::interfaces() {
        // skip interface if its down, is localhost or is empty/virtual
        if !iface.is_lower_up() || iface.is_loopback() || iface.ips.is_empty() || iface.mac.is_none() {
            continue;
        }

        interfaces.push(iface);
    }
    interfaces
}

// helper function to check if a reply is from a functional device
fn check_packets(mut rx: Box<dyn DataLinkReceiver>, list: &mut Vec<Device>) {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(3);

    while start.elapsed() < timeout {
        match rx.next() {
           Ok(packet_bytes) => {
                if let Some(eth_packet) = EthernetPacket::new(packet_bytes) {
                    if eth_packet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp_packet) = ArpPacket::new(eth_packet.payload()) {
                            if arp_packet.get_operation() == ArpOperations::Reply {
                                let active_ip = arp_packet.get_sender_proto_addr();
                                let active_mac = arp_packet.get_sender_hw_addr();

                                list.push(Device {
                                    address: active_ip,
                                    mac: active_mac,
                                });
                            }
                        }
                    }
                }
            }
            // timeout
            Err(_) => { break; }
        }
    }
}
