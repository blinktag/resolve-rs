use crate::buf::BytePacketBuffer;

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
       // AAAA, etc...
}

impl QueryType {
    pub fn from_u16(value: u16) -> QueryType {
        match value {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(value),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::UNKNOWN(value) => *value,
        }
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

        let typenum = self.query_type.to_u16();
        buffer.write_u16(typenum)?;
        buffer.write_u16(0)?;

        Ok(())
    }
}
