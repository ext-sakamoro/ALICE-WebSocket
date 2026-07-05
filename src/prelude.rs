//! Convenience re-export (= `use alice_websocket::prelude::*;`).

pub use crate::assembler::{Message, MessageAssembler};
pub use crate::base64::{base64_decode, base64_encode};
pub use crate::buffer::FrameBuffer;
pub use crate::close_code::{validate_close_code, CloseCode};
pub use crate::close_payload::ClosePayload;
pub use crate::errors::WsError;
pub use crate::extensions::{Extension, ExtensionParam};
pub use crate::frame::Frame;
pub use crate::handshake::{
    compute_accept_key, HandshakeRequest, HandshakeResponse, Header, WEBSOCKET_GUID,
};
pub use crate::masking::{apply_mask, apply_mask_in_place};
pub use crate::opcode::Opcode;
