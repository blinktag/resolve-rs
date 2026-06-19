use crate::buf::BytePacketBuffer;
use crate::record::packet::DnsPacket;
use crate::record::question::{DnsQuestion, QueryType};
use crate::record::result::ResultCode;
use anyhow::anyhow;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use tokio::net::UdpSocket;
use tracing::{debug, error, info};

#[derive(Debug)]
pub struct ResolverService {
    cache: RwLock<HashMap<String, DnsPacket>>,
}

impl ResolverService {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    #[tracing::instrument(name = "Checking cache for question", skip(dns_question))]
    fn get_cached_question(&self, dns_question: &DnsQuestion) -> Option<DnsPacket> {
        println!("Checking cache for {:?}", dns_question.to_cache_key());
        let cache = self.cache.read().unwrap();
        match cache.get(&dns_question.name) {
            Some(answer) => Some(answer.clone()),
            None => None,
        }
    }

    #[tracing::instrument(name = "Setting cache for question", skip(question, answer))]
    pub fn set_cached_question(
        &self,
        question: DnsQuestion,
        answer: DnsPacket,
    ) -> anyhow::Result<()> {
        let mut cache = match self.cache.write() {
            Ok(cache) => cache,
            Err(_) => return Err(anyhow!("Failed to acquire cache lock")),
        };

        match cache.insert(question.to_cache_key(), answer) {
            Some(_) => Ok(()),
            None => Err(anyhow!("Failed to insert cache entry")),
        }
    }

    // Ask up the authority chain
    #[tracing::instrument(name = "Performing lookup to remote server",
        fields(
query_name = query_name,
query_type = query_type.to_string(),
header_id = header_id,
server = %{ server.0 }
        ) )]
    async fn lookup(
        &self,
        query_name: &str,
        query_type: QueryType,
        header_id: u16,
        server: (Ipv4Addr, u16),
    ) -> anyhow::Result<DnsPacket> {
        // Using port 0 will let the OS pick a random port
        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;

        let mut packet = DnsPacket::new();
        packet.header.id = header_id;
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

    #[tracing::instrument(name = "Handling query", skip(request),
        fields(
query_name = request.questions.first().unwrap().name,
query_type = request.questions.first().unwrap().query_type.to_string(),
header_id = request.header.id
        ))]
    pub async fn handle_query(&self, mut request: DnsPacket) -> anyhow::Result<Vec<u8>> {
        let mut packet = DnsPacket::new();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;

        if let Some(question) = request.questions.pop() {
            // Check if we have a cached response
            debug!("Received query: {:?}", question);

            // Handle cache
            match self.get_cached_question(&question) {
                Some(mut q) => {
                    info!("Cache hit: {:?}", q);
                    let mut res_buffer = BytePacketBuffer::new();
                    q.write(&mut res_buffer)?;

                    let len = res_buffer.pos();
                    let data = res_buffer.get_range(0, len)?;

                    // TODO: TTL check
                    return Ok(data.to_vec());
                }
                _ => {
                    info!("Cache miss");
                }
            }

            packet.header.rescode = ResultCode::FORMERR; // default
            if let Ok(result) = self
                .recursive_lookup(&question.name, question.query_type, request.header.id)
                .await
            {
                packet.questions.push(question.clone());
                packet.header.rescode = result.header.rescode;

                result
                    .answers
                    .iter()
                    .for_each(|rec| packet.answers.push(rec.to_owned()));

                // Some responses might return multiple answers, so we'll just take the first one
                if let Some(answer) = packet.answers.first() {
                    debug!("Answer: {:?}", answer);
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

            // Set packet to cache
            if packet.header.rescode == ResultCode::NOERROR {
                info!("Caching response");
                match self.set_cached_question(question, packet.clone()) {
                    Ok(_) => {}
                    Err(e) => error!("Failed to set cache: {:?}", e),
                }
            }
        }

        let mut res_buffer = BytePacketBuffer::new();
        packet.write(&mut res_buffer)?;

        let len = res_buffer.pos();
        let data = res_buffer.get_range(0, len)?;

        // Still need send_to() after this
        Ok(data.to_vec())
    }

    #[tracing::instrument(
        name = "Performing recursive lookup",
        fields(
        query_name = query_name,
        query_type = query_type.to_string(),
        header_id = header_id
        )
    )]
    async fn recursive_lookup(
        &self,
        query_name: &str,
        query_type: QueryType,
        header_id: u16,
    ) -> anyhow::Result<DnsPacket> {
        // Start with a.root-servers.net
        let mut ns = "198.41.0.4".parse::<Ipv4Addr>()?;

        // We don't know how many hops it will take to resolve, so loop
        const MAX_HOPS: u8 = 10;
        let mut hops = 0;
        while hops < MAX_HOPS {
            hops += 1;
            debug!("Resolving {:?}  {} with {}", query_type, query_name, ns);

            let server = (ns, 53);
            let response = self
                .lookup(query_name, query_type, header_id, server)
                .await?;

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
                None => return Err(anyhow!("No NS record found")),
            };

            // Find the A record for the NS since we didn't get one in the answer section
            let recursive_response =
                Box::pin(self.recursive_lookup(&new_ns_name, QueryType::A, header_id)).await?;

            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns;
            } else {
                return Ok(response);
            }
        }

        Err(anyhow!("Max hops reached"))
    }
}
