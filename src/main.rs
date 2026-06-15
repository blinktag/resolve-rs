use crate::buf::BytePacketBuffer;
use crate::record::packet::DnsPacket;
use crate::record::question::{DnsQuestion, QueryType};
use crate::record::result::ResultCode;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

pub mod buf;
pub mod record;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Using Arc since we will spawn a thread for each connection
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", 2053)).await?);

    // Max 256 concurrent queries
    let limiter = Arc::new(Semaphore::new(256));

    loop {
        // Receive done in main() so that we can handle multiple queries at once.
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = socket.recv_from(&mut req_buffer.buf).await?;
        let request = DnsPacket::from_buffer(&mut req_buffer)?;

        let socket = Arc::clone(&socket);
        let limiter = Arc::clone(&limiter);

        tokio::spawn(async move {
            let _permit = limiter.acquire().await;
            let response = handle_query(request).await?;
            socket.send_to(&response, src).await?;

            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
    }
}

// Ask up the authority chain
async fn lookup(
    query_name: &str,
    query_type: QueryType,
    server: (Ipv4Addr, u16),
) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    // Using port 0 will let the OS pick a random port
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;

    let mut packet = DnsPacket::new();
    packet.header.id = 4444; // TODO: Generate random ID?
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(query_name.into(), query_type));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket
        .send_to(&req_buffer.buf[0..req_buffer.pos], server)
        .await?;

    let mut resp_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut resp_buffer.buf).await?;

    let res_packet = DnsPacket::from_buffer(&mut resp_buffer)?;
    Ok(res_packet)
}

async fn handle_query<'a>(
    mut request: DnsPacket,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        packet.header.rescode = ResultCode::FORMERR; // default
        if let Ok(result) = recursive_lookup(&question.name, question.query_type).await {
            packet.questions.push(question.clone());
            packet.header.rescode = result.header.rescode;

            result
                .answers
                .iter()
                .for_each(|rec| packet.answers.push(rec.to_owned()));

            // Some responses might return multiple answers, so we'll just take the first one
            if let Some(answer) = packet.answers.first() {
                println!("Answer: {:?}", answer);
            }

            result
                .authorities
                .iter()
                .for_each(|rec| packet.authorities.push(rec.to_owned()));

            result
                .resources
                .iter()
                .for_each(|rec| packet.resources.push(rec.to_owned()));
        } else {
            packet.header.rescode = ResultCode::SERVFAIL;
        }
    }

    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    //socket.send_to(&data, src).await?;

    // Still need send_to() after this
    Ok(data.to_vec())
}

async fn recursive_lookup(
    query_name: &str,
    query_type: QueryType,
) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    // Start with a.root-servers.net
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>()?;

    // We don't know how many hops it will take to resolve, so loop
    const MAX_HOPS: u8 = 10;
    let mut hops = 0;
    while hops < MAX_HOPS {
        hops += 1;
        println!("Resolving {:?}  {} with {}", query_type, query_name, ns);

        let ns_copy = ns.clone();

        let server = (ns_copy, 53);
        let response = lookup(query_name, query_type, server).await?;

        // We have our answer
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        // NXDOMAIN => authoritative section tells us the domain doesn't exist
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // Did we get a NS record + IP? If so, we'll use it to resolve the query
        if let Some(new_ns) = response.get_resolved_ns(query_name) {
            ns = new_ns;
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(query_name) {
            Some(name) => name,
            None => return Err("No NS record found".into()),
        };

        // Find the A record for the NS since we didn't get one in the answer section
        let recursive_response = Box::pin(recursive_lookup(&new_ns_name, QueryType::A)).await?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }

    Err("Max hops reached".into())
}
