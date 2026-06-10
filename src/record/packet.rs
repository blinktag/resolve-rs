use crate::buf::BytePacketBuffer;
use crate::record::header::DnsHeader;
use crate::record::question::{DnsQuestion, QueryType};
use crate::record::record::DnsRecord;

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
}
