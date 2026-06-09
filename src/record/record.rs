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
