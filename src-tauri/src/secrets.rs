use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::SentinelError;

pub const GEMINI_BYOK_TARGET: &str = "WinPulseSentinel/GeminiByokApiKey";

pub trait SecretStore: Send + Sync {
    fn get_secret(&self, target: &str) -> Result<Option<String>, SentinelError>;
    fn set_secret(&self, target: &str, value: &str) -> Result<(), SentinelError>;
    fn delete_secret(&self, target: &str) -> Result<(), SentinelError>;
}

pub fn mask_secret(secret: &str) -> String {
    let trimmed = secret.trim();
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= 6 {
        return "••••••".to_string();
    }
    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars.iter().rev().take(2).copied().collect::<Vec<_>>().into_iter().rev().collect();
    format!("{prefix}••••••••{suffix}")
}

#[derive(Default, Clone)]
pub struct MemorySecretStore {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemorySecretStore {
    fn get_secret(&self, target: &str) -> Result<Option<String>, SentinelError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| SentinelError::Internal("secret store mutex poisoned".to_string()))?;
        Ok(guard.get(target).cloned())
    }

    fn set_secret(&self, target: &str, value: &str) -> Result<(), SentinelError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SentinelError::Internal("secret store mutex poisoned".to_string()))?;
        guard.insert(target.to_string(), value.to_string());
        Ok(())
    }

    fn delete_secret(&self, target: &str) -> Result<(), SentinelError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SentinelError::Internal("secret store mutex poisoned".to_string()))?;
        guard.remove(target);
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Default, Clone, Copy)]
pub struct WindowsCredentialStore;

#[cfg(windows)]
impl SecretStore for WindowsCredentialStore {
    fn get_secret(&self, target: &str) -> Result<Option<String>, SentinelError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::ERROR_NOT_FOUND;
        use windows::Win32::Security::Credentials::{
            CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
        };

        let wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();

        // SAFETY: wide is valid null-terminated UTF-16; cred_ptr is freed via CredFree on success.
        let res = unsafe { CredReadW(PCWSTR(wide.as_ptr()), CRED_TYPE_GENERIC, Some(0), &mut cred_ptr) };
        match res {
            Ok(()) => {
                if cred_ptr.is_null() {
                    return Ok(None);
                }
                // SAFETY: cred_ptr was allocated by CredReadW; CredentialBlobSize bytes are valid.
                let secret = unsafe {
                    let cred = &*cred_ptr;
                    let slice = if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
                        &[]
                    } else {
                        std::slice::from_raw_parts(
                            cred.CredentialBlob,
                            cred.CredentialBlobSize as usize,
                        )
                    };
                    let decoded = String::from_utf8_lossy(slice).trim().to_string();
                    CredFree(cred_ptr.cast());
                    decoded
                };
                if secret.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(secret))
                }
            }
            Err(err) if err.code() == ERROR_NOT_FOUND.to_hresult() => Ok(None),
            Err(err) => Err(SentinelError::Internal(format!(
                "CredReadW failed: {err}"
            ))),
        }
    }

    fn set_secret(&self, target: &str, value: &str) -> Result<(), SentinelError> {
        use windows::core::PWSTR;
        use windows::Win32::Security::Credentials::{
            CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
        };

        let mut wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let mut blob = value.trim().as_bytes().to_vec();
        let cred = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(wide.as_mut_ptr()),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };

        // SAFETY: wide and blob stay alive and unmodified for the duration of CredWriteW.
        unsafe { CredWriteW(&cred, 0) }
            .map_err(|err| SentinelError::Internal(format!("CredWriteW failed: {err}")))
    }

    fn delete_secret(&self, target: &str) -> Result<(), SentinelError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::ERROR_NOT_FOUND;
        use windows::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};

        let wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: wide is valid null-terminated UTF-16.
        match unsafe { CredDeleteW(PCWSTR(wide.as_ptr()), CRED_TYPE_GENERIC, Some(0)) } {
            Ok(()) => Ok(()),
            Err(err) if err.code() == ERROR_NOT_FOUND.to_hresult() => Ok(()),
            Err(err) => Err(SentinelError::Internal(format!(
                "CredDeleteW failed: {err}"
            ))),
        }
    }
}

pub fn default_secret_store() -> Arc<dyn SecretStore> {
    #[cfg(windows)]
    {
        Arc::new(WindowsCredentialStore)
    }
    #[cfg(not(windows))]
    {
        Arc::new(MemorySecretStore::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_secret_store_roundtrip_and_masking() {
        let store = MemorySecretStore::new();
        let synthetic_key = format!("{}{}", "AIza", "SyFakeUnitTestKey9876");
        assert_eq!(store.get_secret(GEMINI_BYOK_TARGET).expect("get"), None);
        store
            .set_secret(GEMINI_BYOK_TARGET, &synthetic_key)
            .expect("set");
        let got = store.get_secret(GEMINI_BYOK_TARGET).expect("get2");
        assert_eq!(got.as_deref(), Some(synthetic_key.as_str()));
        assert_eq!(mask_secret(&synthetic_key), "AIza••••••••76");
        store.delete_secret(GEMINI_BYOK_TARGET).expect("del");
        assert_eq!(store.get_secret(GEMINI_BYOK_TARGET).expect("get3"), None);
    }
}
