use crate::buf::BytePacketBuffer;
use crate::record::packet::DnsPacket;
use crate::record::question::{DnsQuestion, QueryType};
use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;

pub mod buf;
pub mod record;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //write_packet()
    //read_packet()
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => (),
            Err(e) => println!("Error: {}", e),
        }
    }
}

fn handle_query(socket: &UdpSocket) -> Result<(), Box<dyn std::error::Error>> {
    let mut req_buffer = BytePacketBuffer::new();
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut packet = DnsPacket::new();
    packet.header.id = 4444;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    Ok(())
}

fn write_packet() -> Result<(), Box<dyn std::error::Error>> {
    let qname = "yahoo.com";
    let qtype = QueryType::AAAA;

    let server = ("8.8.8.8", 53);

    let mut packet = DnsPacket::new();
    packet.header.id = 4444;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // Using a range here to .pos since we allocate 512b for the buffer
    // when it's created, and we might not necessarily need the entire buffer.
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut resp_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut resp_buffer.buf)?;

    // Convert the response data into a DnsPacket
    let res_packet = DnsPacket::from_buffer(&mut resp_buffer)?;
    println!("{:#?}", res_packet.header);

    res_packet.answers.iter().for_each(|a| println!("{:#?}", a));
    res_packet
        .authorities
        .iter()
        .for_each(|a| println!("{:#?}", a));
    res_packet
        .resources
        .iter()
        .for_each(|a| println!("{:#?}", a));
    res_packet
        .questions
        .iter()
        .for_each(|a| println!("{:#?}", a));

    Ok(())
}

#[allow(dead_code)]
fn read_packet() -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
