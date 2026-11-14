#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    BufferUnderrun,
    InvalidTag,
    InvalidLength,
    InvalidValue,
    DuplicateTag,
    MissingRequiredField,
}
