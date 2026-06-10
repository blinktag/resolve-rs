use crate::buf::BytePacketBuffer;
use crate::record::result::ResultCode;

#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    // Packet identifier (16 bits)
    // A random identifier is assigned to query packets. Response packets must reply with the
    // same id. This is needed to differentiate responses due to the stateless nature of UDP.
    pub id: u16,

    // ----------- Flags -----------

    // ------ First 8 bits ------

    // Recursion Desired (1 bit)
    // Set by the sender if the server should attempt to resolve the query recursively if it
    // does not have an answer readily available.
    pub recursion_desired: bool,

    // Truncated message (1 bit)
    // Set to 1 if the message length exceeds 512 bytes
    pub truncated_message: bool,

    // Authoritative answer (1 bit)
    // Set to 1 if the response is authoritative.
    pub authoritative_answer: bool,

    // Operation code (4 bits)
    // Typically always `0` for queries.
    pub op_code: u8,

    // Query response (1 bit)
    // Set to 1 for a query, 0 for a response.
    pub response: bool,

    // --------- End First 8 bits ---------

    // --------- Second 8 bits ---------

    // Response code (4 bits)
    // Set by server to indicate success or failure of the query.
    pub rescode: ResultCode, // 4 bits

    // Checking Disabled (CD) (1 bit)
    // Set by the sender to disable DNSSEC validation by the resolver.
    pub checking_disabled: bool,

    // Authenticated data (1 bit)
    // Set by the resolver to indicate that DNSSEC validation succeeded.
    pub authed_data: bool,

    // Reserved (3 bits)
    pub _z: bool,

    // Recursion available (1 bit)
    // Set by the server to indicate whether recursive queries are allowed.
    pub recursion_available: bool,

    // --------- End Second 8 bits ---------

    // --------- End Flags ---------

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
        //   0001_0001 <-- bytes from packet
        // & 0000_1111 <-- mask off everything but the lowest 4 bits
        //   ---- ----
        // = 0000_0001 <-- opcode
        self.op_code = (a >> 3) & 0x0F;

        // Check bit 7 for query or response
        // 1 = query, 0 = response
        self.response = (a & (1 << 7)) > 0;

        // Straight read of 1 byte for the response code
        self.rescode = ResultCode::from_u8(b & 0x0F);

        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self._z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        // Next 4 bytes are the number of questions, answers, etc.
        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        // First field is ID
        buffer.write_u16(self.id)?;

        // Write our flags, 16 bits total

        // First 8 bits are the flags
        buffer.write_u8(
            (self.recursion_desired as u8)
                | (self.truncated_message as u8) << 1
                | (self.authoritative_answer as u8) << 2
                | (self.op_code as u8) << 3
                | (self.response as u8) << 7,
        )?;

        // Second 8 bits are the data length
        buffer.write_u8(
            (self.rescode as u8)
                | (self.checking_disabled as u8) << 4
                | (self.authed_data as u8) << 5
                | (self._z as u8) << 6
                | (self.recursion_available as u8) << 7,
        )?;

        // Data length fields - 2 bits each
        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}
