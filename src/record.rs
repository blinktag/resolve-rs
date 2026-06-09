#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,          // 12 bytes
    pub question: Vec<Question>, // variable
    pub answer: Vec<Record>,     // variable
    pub authority: Vec<Record>,  // variable
    pub additional: Vec<Record>, // variable
}

#[derive(Clone, Debug)]
pub struct Header {
    // Packet identifier (16 bits)
    // A random identifier is assigned to query packets. Response packets must reply with the
    // same id. This is needed to differentiate responses due to the stateless nature of UDP.
    pub id: u16,

    // Query response (1 bit)
    // Set to 1 for a query, 0 for a response.
    pub query_response: bool,

    // Operation code (4 bits)
    // Typically always `0` for queries.
    pub op_code: u8,

    // Authoritative answer (1 bit)
    // Set to 1 if the response is authoritative.
    pub aa: bool,

    // Truncated message (1 bit)
    // Set to 1 if the message length exceeds 512 bytes
    pub tc: bool,

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
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
