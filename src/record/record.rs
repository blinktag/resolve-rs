use crate::buf::BytePacketBuffer;
use crate::record::question::QueryType;
use std::net::Ipv4Addr;

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
                let addr = Ipv4Addr::from(raw_addr);
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

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize, String> {
        let start_pos = buffer.pos();

        match &self {
            DnsRecord::A {
                domain,
                address,
                ttl,
            } => {
                buffer.write_qname(domain)?; // Domain labels
                buffer.write_u16(QueryType::A.to_u16())?; // Record type
                buffer.write_u16(1)?; // TODO: what field is this?
                buffer.write_u32(*ttl)?;
                buffer.write_u16(4)?; // TODO: what field is this?
                buffer.write_u32(address.to_bits())?;
            }
            DnsRecord::UNKNOWN { .. } => {
                eprintln!("Skipping record: {:?}", self)
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}
