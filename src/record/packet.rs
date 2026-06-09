use crate::record::header::DnsHeader;
use crate::record::record::{Question, Record};

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: DnsHeader,       // 12 bytes
    pub question: Vec<Question>, // variable
    pub answer: Vec<Record>,     // variable
    pub authority: Vec<Record>,  // variable
    pub additional: Vec<Record>, // variable
}
