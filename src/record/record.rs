use crate::buf::BytePacketBuffer;
use crate::record::question::QueryType;
use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct RecordPreamble {
    // The domain name, encoded as a sequence of labels, terminated by a null byte.
    name: String,

    // Record Type (2 bytes)
    rtype: u16,

    // The class of the record (2 bytes)
    // Typically `1` for most cases
    class: u16,

    // Time-To-Live (4 bytes)
    // Defines how long to cache the record for.
    ttl: u32,

    // Length of the data specific to the record type (2 bytes)
    len: u16,
}

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
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, String> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let query_type_raw: u16 = buffer.read_u16()?;
        let query_type: QueryType = QueryType::from_u16(query_type_raw);
        let _ = buffer.read_u16()?; // TODO: what is this?
        let ttl: u32 = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match query_type {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );
                // TODO: can we replace ^ with below?
                //let addr = Ipv4Addr::from(raw_addr);
                Ok(DnsRecord::A {
                    domain,
                    address: addr,
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
}
