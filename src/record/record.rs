use crate::buf::BytePacketBuffer;
use crate::record::question::{QueryClass, QueryType};
use anyhow::Result;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::warn;

pub const TERMINATOR: u8 = 0;

// RDLENGTH (16bit) specifies the length of the resource record in bytes.
// This value is fixed for A or AAAA records, but can be variable for TXT/SRV records
pub const FIXED_RD_LENGTH: u16 = 4;

#[derive(Clone, Debug)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        query_type: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        address: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    // SOA {
    //     domain: String,
    //     host: String,
    //     ttl: u32,
    // },
    // PTR {
    //     domain: String,
    //     host: String,
    //     ttl: u32,
    // },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    // TXT {
    //     domain: String,
    //     data: String,
    //     ttl: u32,
    // },
    AAAA {
        domain: String,
        address: Ipv6Addr,
        ttl: u32,
    },
    // SRV {
    //     domain: String,
    //     priority: u16,
    //     weight: u16,
    //     port: u16,
    //     host: String,
    // },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let query_type_raw: u16 = buffer.read_u16()?;
        let query_type: QueryType = QueryType::from_u16(query_type_raw);
        let _ = buffer.read_u16()?; // CLASS
        let ttl: u32 = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match query_type {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::from(raw_addr);
                Ok(DnsRecord::A {
                    domain,
                    address: addr,
                    ttl,
                })
            }
            QueryType::NS => {
                // Value reuses the same label semantics as `qname`
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority: u16 = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let address = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA {
                    domain,
                    address,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    query_type: query_type_raw,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match &self {
            DnsRecord::A {
                domain,
                address,
                ttl,
            } => {
                buffer.write_qname(domain)?; // Domain labels
                buffer.write_u16(QueryType::A.to_u16())?; // Record type
                buffer.write_u16(QueryClass::IN.to_u16())?;
                buffer.write_u32(ttl.clone())?;
                buffer.write_u16(FIXED_RD_LENGTH)?;
                buffer.write_u32(address.to_bits())?;
            }
            DnsRecord::NS { domain, host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_u16())?;
                buffer.write_u16(QueryClass::IN.to_u16())?;
                buffer.write_u32(ttl.clone())?;

                // We will need this to set the data length a few lines below
                let pos = buffer.pos();
                buffer.write_u16(TERMINATOR as u16)?;

                buffer.write_qname(host)?;

                // Doing plus 2 here because we have to account for the length of the name + the length byte + terminator
                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                domain,
                address,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_u16())?;
                buffer.write_u16(QueryClass::IN.to_u16())?;
                buffer.write_u32(ttl.clone())?;
                buffer.write_u16(16)?; // length

                for octet in &address.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                warn!("Skipping record: {:?}, unhandled type", self)
            }
            _ => {
                // ignore for now
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}
