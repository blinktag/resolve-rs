use crate::buf::BytePacketBuffer;

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: DnsHeader,       // 12 bytes
    pub question: Vec<Question>, // variable
    pub answer: Vec<Record>,     // variable
    pub authority: Vec<Record>,  // variable
    pub additional: Vec<Record>, // variable
}

#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    // Packet identifier (16 bits)
    // A random identifier is assigned to query packets. Response packets must reply with the
    // same id. This is needed to differentiate responses due to the stateless nature of UDP.
    pub id: u16,

    // Query response (1 bit)
    // Set to 1 for a query, 0 for a response.
    pub response: bool,

    // Operation code (4 bits)
    // Typically always `0` for queries.
    pub op_code: u8,

    // Authoritative answer (1 bit)
    // Set to 1 if the response is authoritative.
    pub authoritative_answer: bool,

    // Truncated message (1 bit)
    // Set to 1 if the message length exceeds 512 bytes
    pub truncated_message: bool,

    // Recursion Desired (1 bit)
    // Set by the sender if the server should attempt to resolve the query recursively if it
    // does not have an answer readily available.
    pub recursion_desired: bool,

    // Recursion available (1 bit)
    // Set by the server to indicate whether recursive queries are allowed.
    pub recursion_available: bool,

    // Reserved (3 bits)
    pub _z: bool,

    // Response code (4 bits)
    // Set by server to indicate success or failure of the query.
    pub result_code: ResultCode, // 4 bits

    // Number of questions (16 bits)
    pub questions: u16, // 16 bits

    // Number of answer records (16 bits)
    pub answers: u16, // 16 bits

    // Number of authority (NS) records (16 bits)
    pub authoritative_entries: u16, // 16 bits

    // Number of additional records (16 bits)
    pub resource_entries: u16, // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader::default()
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        // ID will be the first 2 bytes of the packet
        self.id = buffer.read_u16()?;

        // Next two bytes are boolean flags
        let flags = buffer.read_u16()?;

        // Split the 16-bit flags into 8-bit fields
        // aaaaaaabbbbbbb
        // Turns into:
        // aaaaaaaa   bbbbbbb
        // ^^^^^^^^   ^^^^^^^
        // byte 1(a)  byte 2(b)
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        /*
           bit:   7   6 5 4 3   2   1   0
                  QR  Opcode    AA  TC  RD

           bit 7       QR      response?
           bits 6-3    Opcode  query type
           bit 2       AA      authoritative answer
           bit 1       TC      message is truncated?
           bit 0       RD      recursion desired
        */

        // Check bit 0 for recursion desired
        self.recursion_desired = (a & (1 << 0)) > 0;

        // Check bit 1 for truncated message
        self.truncated_message = (a & (1 << 1)) > 0;

        // Check bit 2 for authoritative answer
        self.authoritative_answer = (a & (1 << 2)) > 0;

        // Check bit 3 to 6 for opcode
        // 1000_1000 >> 3 = 0001_0001
        //                       ^^^^ this is where the opcode is now
        // Then we AND with 0x0F to get the lowest 4 bits:
        //   0001_0001 <-- byts from packet
        // & 0000_1111 <-- mask off everything but the lowest 4 bits
        //   ---- ----
        // = 0000_0001 <-- opcode
        self.op_code = (a >> 3) & 0x0F;

        // Check bit 7 for query or response
        // 1 = query, 0 = response
        self.response = (a & (1 << 7)) > 0;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Question {
    // The domain name, encoded as a sequence of labels, terminated by a null byte.
    name: String,

    // Record Type (2 bytes)
    // Prefixed with `r` because `type` is a keyword in Rust
    rtype: u16,

    //  The class of the record (2 bytes)
    // Typically `1` for most cases
    class: u16,
}

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
pub struct Record {
    preamble: RecordPreamble,
    data: RecordData,
}

#[derive(Clone, Debug)]
pub enum RecordData {
    A([u8; 4]),
    AAAA([u8; 16]),
    CNAME(String),
    MX {
        preference: u16,
        exchange: String,
    },
    NS(String),
    PTR(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    TXT(String),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum ResultCode {
    #[default]
    NOERROR = 0,

    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }

    pub fn from_u8(num: u8) -> ResultCode {
        ResultCode::from_num(num)
    }
}
