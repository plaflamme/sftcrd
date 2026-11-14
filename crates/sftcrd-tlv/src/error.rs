#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferUnderrun,
    InvalidLength,
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
