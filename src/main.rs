use crate::buf::BytePacketBuffer;
use crate::record::packet::DnsPacket;
use crate::record::question::{DnsQuestion, QueryType};
use crate::record::result::ResultCode;
use std::net::{Ipv4Addr, UdpSocket};

pub mod buf;
pub mod record;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => (),
            Err(e) => println!("Error: {}", e),
        }
    }
}

// Ask up the authority chain
fn lookup(
    qname: &str,
    qtype: QueryType,
    server: (Ipv4Addr, u16),
) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 4444;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.into(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    let mut resp_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut resp_buffer.buf)?;

    let res_packet = DnsPacket::from_buffer(&mut resp_buffer)?;
    Ok(res_packet)
}

fn handle_query(socket: &UdpSocket) -> Result<(), Box<dyn std::error::Error>> {
    let mut req_buffer = BytePacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        packet.header.rescode = ResultCode::FORMERR; // default
        if let Ok(result) = recursive_lookup(&question.name, question.query_type) {
            packet.questions.push(question.clone());
            packet.header.rescode = result.header.rescode;

            for rec in result.answers {
                packet.answers.push(rec);
            }

            packet
                .answers
                .iter()
                .take(1)
                .for_each(|rec| println!("Answer: {:?}", rec));

            for rec in result.authorities {
                packet.authorities.push(rec);
            }

            for rec in result.resources {
                packet.resources.push(rec);
            }
        } else {
            packet.header.rescode = ResultCode::SERVFAIL;
        }
    }

    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(&data, src)?;

    Ok(())
}

fn recursive_lookup(
    qname: &str,
    qtype: QueryType,
) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    // Start with a.root-servers.net
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>()?;

    // We don't know how many hops it will take to resolve, so loop
    const MAX_HOPS: u8 = 10;
    let mut hops = 0;
    while hops < MAX_HOPS {
        hops += 1;
        println!("Resolving {:?}  {} with {}", qtype, qname, ns);

        let ns_copy = ns.clone();

        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        // We have our answer
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        // NXDOMAIN => authoritative section tells us the domain doesn't exist
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // Did we get a NS record + IP? If so, we'll use it to resolve the query
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(name) => name,
            None => return Err("No NS record found".into()),
        };

        // Find the A record for the NS since we didn't get one in the answer section
        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }

    return Err("Max hops reached".into());
}
