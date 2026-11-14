use super::DecodeError;

pub trait ValueDecoder<'a>
where
    Self: Sized,
{
    fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError>;
}

impl ValueDecoder<'_> for u8 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if let [byte] = bytes {
            Ok(*byte)
        } else {
            Err(DecodeError::BufferUnderrun)
        }
    }
}

impl ValueDecoder<'_> for u16 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if let [msb, lsb] = bytes {
            Ok(u16::from_be_bytes([*msb, *lsb]))
        } else {
            Err(DecodeError::BufferUnderrun)
        }
    }
}

impl ValueDecoder<'_> for Vec<u8> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Vec::from(bytes))
    }
}

impl<'a> ValueDecoder<'a> for &'a [u8] {
    fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        Ok(bytes)
    }
}

pub trait ValueEncoder {
    fn length(&self) -> usize;
    fn encode(&self, buf: &mut [u8]);

    fn encode_top_level(&self) -> Vec<u8> {
        let mut value = vec![0; self.length()];
        self.encode(&mut value);
        value
    }
}

impl ValueEncoder for u8 {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) {
        buf[0] = *self;
    }
}

impl ValueEncoder for u16 {
    fn length(&self) -> usize {
        2
    }

    fn encode(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.to_be_bytes());
    }
}

impl ValueEncoder for &[u8] {
    fn length(&self) -> usize {
        self.len()
    }

    fn encode(&self, buf: &mut [u8]) {
        buf.copy_from_slice(self);
    }
}

impl ValueEncoder for Vec<u8> {
    fn length(&self) -> usize {
        self.len()
    }

    fn encode(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self);
    }
}

impl<T> ValueEncoder for Option<T>
where
    T: ValueEncoder,
{
    fn length(&self) -> usize {
        match self {
            None => 0,
            Some(v) => v.length(),
        }
    }

    fn encode(&self, buf: &mut [u8]) {
        match self {
            None => (),
            Some(v) => v.encode(buf),
        }
    }
}
