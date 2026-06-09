fn main() {

}

pub struct Packet  {
    header: Header, // 12 bytes
    question: Vec<Question>, // variable
    answer: Vec<Record>, // variable
    authority: Vec<Record>, // variable
    additional: Vec<Record>, // variable
}

pub struct Header  {
    // Packet identifier (16 bits)
    // A random identifier is assigned to query packets. Response packets must reply with the
    // same id. This is needed to differentiate responses due to the stateless nature of UDP.
    id: u16,

    // Query response (1 bit)
    // Set to 1 for a query, 0 for a response.
    qr: u8,

    // Operation code (4 bits)
    // Typically always `0` for queries.
    opCode: u8,

    // Authoritative answer (1 bit)
    // Set to 1 if the response is authoritative.
    aa: u8,

    // Truncated message (1 bit)
    // Set to 1 if the message length exceeds 512 bytes
    tc: u8,

    // Recursion Desired (1 bit)
    // Set by the sender if the server should attempt to resolve the query recursively if it
    // does not have an answer readily available.
    rd: u8,

    // Recursion available (1 bit)
    // Set by the server to indicate whether recursive queries are allowed.
    ra: u8,

    // Reserved (3 bits)
    _z: u8,

    // Response code (4 bits)
    // Set by server to indicate success or failure of the query.
    rcode: u8, // 4 bits

    // Number of questions (16 bits)
    qdCount: u16, // 16 bits

    // Number of answer records (16 bits)
    anCount: u16, // 16 bits

    // Number of authority records (16 bits)
    nsCount: u16, // 16 bits

    // Number of additional records (16 bits)
    arCount: u16, // 16 bits
}

pub struct Question  {
    name: String,
    qtype: u16, //2 bytes
    qclass: u16, // 2 bytes
}
pub struct Record  {}