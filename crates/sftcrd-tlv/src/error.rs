#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferUnderrun,
    InvalidLength,
    InvalidValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    BufferUnderrun,
    InvalidTag,
    InvalidLength,
    InvalidValue,
    DuplicateTag,
    MissingRequiredField,
}
