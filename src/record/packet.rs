use crate::buf::BytePacketBuffer;
use crate::record::header::DnsHeader;
use crate::record::question::{DnsQuestion, QueryType};
use crate::record::record::DnsRecord;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Default)]
pub struct DnsPacket {
    pub header: DnsHeader,           // 12 bytes
    pub questions: Vec<DnsQuestion>, // variable length
    pub answers: Vec<DnsRecord>,     // variable length
    pub authorities: Vec<DnsRecord>, // variable length
    pub resources: Vec<DnsRecord>,   // variable length
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket::default()
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket, String> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let record = DnsRecord::read(buffer)?;
            result.answers.push(record);
        }

        for _ in 0..result.header.authoritative_entries {
            let record = DnsRecord::read(buffer)?;
            result.authorities.push(record);
        }

        for _ in 0..result.header.resource_entries {
            let record = DnsRecord::read(buffer)?;
            result.resources.push(record);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        self.questions.iter().try_for_each(|q| q.write(buffer))?;

        self.answers
            .iter()
            .try_for_each(|a| a.write(buffer).map(|_| ()))?;

        self.authorities
            .iter()
            .try_for_each(|a| a.write(buffer).map(|_| ()))?;

        self.resources
            .iter()
            .try_for_each(|a| a.write(buffer).map(|_| ()))?;

        Ok(())
    }

    /// It's useful to be able to pick a random A record from a packet. When we
    /// get multiple IP's for a single name, it doesn't matter which one we
    /// choose, so in those cases we can now pick one at random.
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { address, .. } => Some(*address),
                _ => None,
            })
            .next()
    }

    /// A helper function which returns an iterator over all name servers in
    /// the authorities section, represented as (domain, host) tuples
    pub fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(domain))
    }

    /// We'll use the fact that name servers often bundle the corresponding
    /// A records when replying to an NS query to implement a function that
    /// returns the actual IP for an NS record if possible.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        // self.get_ns(qname)
        //     .map(|(_, host)| self.get_random_a().unwrap_or(Ipv4Addr::new(0, 0, 0, 0)))

        self.get_ns(qname)
            // Now we need to look for a matching A record in the additional
            // section. Since we just want the first valid record, we can just
            // build a stream of matching records.
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    // Filter for A records where the domain match the host
                    // of the NS record that we are currently processing
                    .filter_map(move |record| match record {
                        DnsRecord::A {
                            domain, address, ..
                        } if domain == host => Some(*address),
                        _ => None,
                    })
            })
            // Finally, pick the first valid entry
            .next()
    }

    /// However, not all name servers are as that nice. In certain cases there won't
    /// be any A records in the additional section, and we'll have to perform *another*
    /// lookup in the midst. For this, we introduce a method for returning the host
    /// name of an appropriate name server.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}
