use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// Base64 encode the provided buffer using a URL safe scheme with no padding
// TODO: Make this consume and zeroize
pub fn b64_encode(x: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(x)
}
