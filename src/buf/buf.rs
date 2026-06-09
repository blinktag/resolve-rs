pub const MAX_UDP_PACKET_SIZE: usize = 512;
const MAX_JUMPS: usize = 5;

pub struct BytePacketBuffer {
    // Max UDP packet size is 512 bytes
    // TODO: how to handle TCP?
    pub buf: [u8; 512],

    // Keeping track of where we are in the buffer
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        Self {
            buf: [0; 512],
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Advances the position in the buffer, `steps` times.
    pub fn step(&mut self, steps: usize) -> Result<(), ()> {
        self.pos += steps;
        Ok(())
    }

    /// Sets the position in the buffer to `pos`
    pub fn seek(&mut self, pos: usize) -> Result<(), String> {
        self.pos = pos;
        Ok(())
    }

    /// Reads a single byte from the buffer and then advances the position.
    pub fn read(&mut self) -> Result<u8, String> {
        if self.pos >= MAX_UDP_PACKET_SIZE {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Reads a single byte from the buffer without advancing the position.
    pub fn get(&mut self, pos: usize) -> Result<u8, String> {
        if pos >= MAX_UDP_PACKET_SIZE {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Reads a range of bytes from the buffer starting at `start` and going `len` bytes
    /// forward without advancing the position.
    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], String> {
        if start >= MAX_UDP_PACKET_SIZE || len >= MAX_UDP_PACKET_SIZE {
            return Err("End of buffer".into());
        }

        Ok(&self.buf[start..start + len])
    }

    /// Read two bytes, stepping twice forward
    pub fn read_u16(&mut self) -> Result<u16, String> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32, String> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    /// Read a domain name from labels
    /// This gets messy because we can have whole domains or we might have
    /// a jump byte to avoid repeating the domain in the record to save space.
    /// A jump byte tells the reader to jump to an earlier position which will
    /// have the domain name.
    ///
    /// This function will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<(), String> {
        // Keep track of position locally for when we run into a jump
        let mut pos = self.pos();

        // Track if we've jumped
        let mut jumped = false;
        let mut jumps_performed = 0;

        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > MAX_JUMPS {
                return Err(format!("Li,it of {} jumps exceeded", MAX_JUMPS).into());
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // Jump Case
            //
            //
            // If len has the two most significant bits set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xc0) == 0xc0 {
                // Update the buffer position to a point past the current label.
                // We don't want to read the label again.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate the offset and perform the jump
                // by updating our local position variable.
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                jumps_performed += 1;

                continue;
            }

            // Base Case: reading a single label

            // Move past the length byte
            pos += 1;

            // Labels are terminated by an empty label
            if len == 0 {
                break;
            }

            // Append the delimiter to the output buffer
            outstr.push_str(delim);

            // Extract the actual ASCII bytes for this label and append them
            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            // Move our position forward by the length of the label
            pos += len as usize;
        }

        // Go back to the original position
        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}
