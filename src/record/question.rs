use crate::buf::BytePacketBuffer;

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    //SOA,   // 6
    //PTR, // 12
    MX, // 15
    //TXT,   // 16
    AAAA, // 28
          //SRV,   // 33
}

impl QueryType {
    pub fn from_u16(value: u16) -> QueryType {
        match value {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            //6 => QueryType::SOA,
            //12 => QueryType::PTR,
            15 => QueryType::MX,
            //16 => QueryType::TXT,
            28 => QueryType::AAAA,
            //33 => QueryType::SRV,
            _ => QueryType::UNKNOWN(value),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            //QueryType::SOA => 6,
            //QueryType::PTR => 12,
            QueryType::MX => 15,
            //QueryType::TXT => 16,
            QueryType::AAAA => 28,
            //QueryType::SRV => 33,
            QueryType::UNKNOWN(value) => *value,
        }
    }
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[allow(dead_code)]
pub enum QueryClass {
    IN = 1,

    // Unused
    _CH = 3,
    _HS = 4,
    _ANY = 255,
}

impl QueryClass {
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub query_type: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, query_type: QueryType) -> DnsQuestion {
        DnsQuestion { name, query_type }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        buffer.read_qname(&mut self.name)?;
        self.query_type = QueryType::from_u16(buffer.read_u16()?);
        let _ = buffer.read_u16(); // class

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        buffer.write_qname(&self.name)?;

        buffer.write_u16(self.query_type.to_u16())?;
        buffer.write_u16(QueryClass::IN.to_u16())?;

        Ok(())
    }
}
