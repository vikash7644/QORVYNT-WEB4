//! Append-only identity operation storage with signature-verified replay.
//!
//! The file log is a local durability adapter, not a distributed consensus or
//! tamper-proof service. Filesystem permissions, backups, and deployment policy
//! remain the operator's responsibility.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    identity::{IdentityKey, KeyRotation},
    resolver::{IdentityOperation, IdentityResolver, ResolverError},
};

const MAX_RECORD_BYTES: usize = 4096;

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    CorruptLog,
    RecordTooLarge,
    Resolver(ResolverError),
}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self { Self::Io(error) }
}

impl From<ResolverError> for StorageError {
    fn from(error: ResolverError) -> Self { Self::Resolver(error) }
}

/// Pluggable append-only operation log. Implementations must append atomically
/// or return an error without reporting success.
pub trait IdentityLog {
    fn load(&mut self) -> Result<Vec<IdentityOperation>, StorageError>;
    fn append(&mut self, operation: &IdentityOperation) -> Result<(), StorageError>;
}

#[derive(Debug, Clone)]
pub struct FileIdentityLog {
    path: PathBuf,
}

impl FileIdentityLog {
    pub fn open(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }
}

impl IdentityLog for FileIdentityLog {
    fn load(&mut self) -> Result<Vec<IdentityOperation>, StorageError> {
        if !self.path.exists() { return Ok(Vec::new()); }
        let mut file = File::open(&self.path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let mut cursor = 0;
        let mut operations = Vec::new();
        while cursor < bytes.len() {
            if bytes.len() - cursor < 4 { return Err(StorageError::CorruptLog); }
            let length = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
            if length == 0 || length > MAX_RECORD_BYTES || bytes.len() - cursor < length {
                return Err(StorageError::CorruptLog);
            }
            operations.push(decode_operation(&bytes[cursor..cursor + length])?);
            cursor += length;
        }
        Ok(operations)
    }

    fn append(&mut self, operation: &IdentityOperation) -> Result<(), StorageError> {
        let record = encode_operation(operation)?;
        if record.is_empty() || record.len() > MAX_RECORD_BYTES {
            return Err(StorageError::RecordTooLarge);
        }
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        file.write_all(&(record.len() as u32).to_be_bytes())?;
        file.write_all(&record)?;
        file.sync_data()?;
        Ok(())
    }
}

/// Resolver wrapper that writes each verified transition to the log before
/// publishing the updated in-memory state.
pub struct PersistentIdentityResolver<L: IdentityLog> {
    resolver: IdentityResolver,
    log: L,
}

impl<L: IdentityLog> PersistentIdentityResolver<L> {
    pub fn open(mut log: L) -> Result<Self, StorageError> {
        let operations = log.load()?;
        let resolver = IdentityResolver::replay(&operations)?;
        Ok(Self { resolver, log })
    }

    pub fn resolver(&self) -> &IdentityResolver { &self.resolver }

    pub fn register(
        &mut self,
        key: IdentityKey,
        created_at: u64,
        proof: &[u8; 64],
    ) -> Result<(), StorageError> {
        let mut candidate = self.resolver.clone();
        candidate.register(key, created_at, proof)?;
        let operation = candidate.operations().last().ok_or(StorageError::CorruptLog)?;
        self.log.append(operation)?;
        self.resolver = candidate;
        Ok(())
    }

    pub fn rotate(&mut self, rotation: KeyRotation) -> Result<(), StorageError> {
        let mut candidate = self.resolver.clone();
        candidate.rotate(rotation)?;
        let operation = candidate.operations().last().ok_or(StorageError::CorruptLog)?;
        self.log.append(operation)?;
        self.resolver = candidate;
        Ok(())
    }

    pub fn revoke(
        &mut self,
        did: &str,
        revoked_at: u64,
        signature: &[u8; 64],
    ) -> Result<(), StorageError> {
        let mut candidate = self.resolver.clone();
        candidate.revoke(did, revoked_at, signature)?;
        let operation = candidate.operations().last().ok_or(StorageError::CorruptLog)?;
        self.log.append(operation)?;
        self.resolver = candidate;
        Ok(())
    }
}

fn encode_operation(operation: &IdentityOperation) -> Result<Vec<u8>, StorageError> {
    let mut out = Vec::new();
    match operation {
        IdentityOperation::Register { did, created_at, proof } => {
            out.push(1);
            out.extend_from_slice(&created_at.to_be_bytes());
            put_string(&mut out, did)?;
            out.extend_from_slice(proof);
        }
        IdentityOperation::Rotate(rotation) => {
            out.push(2);
            out.extend_from_slice(&rotation.effective_at.to_be_bytes());
            put_string(&mut out, &rotation.old_did)?;
            put_string(&mut out, &rotation.new_did)?;
            out.extend_from_slice(&rotation.old_key_signature);
            out.extend_from_slice(&rotation.new_key_proof);
        }
        IdentityOperation::Revoke { did, revoked_at, signature } => {
            out.push(3);
            out.extend_from_slice(&revoked_at.to_be_bytes());
            put_string(&mut out, did)?;
            out.extend_from_slice(signature);
        }
    }
    Ok(out)
}

fn decode_operation(bytes: &[u8]) -> Result<IdentityOperation, StorageError> {
    let mut cursor = 0;
    let kind = take(bytes, &mut cursor, 1)?[0];
    let timestamp = u64::from_be_bytes(take(bytes, &mut cursor, 8)?.try_into().unwrap());
    let operation = match kind {
        1 => {
            let did = take_string(bytes, &mut cursor)?;
            let proof = take(bytes, &mut cursor, 64)?.try_into().unwrap();
            IdentityOperation::Register { did, created_at: timestamp, proof }
        }
        2 => {
            let old_did = take_string(bytes, &mut cursor)?;
            let new_did = take_string(bytes, &mut cursor)?;
            let old_key_signature = take(bytes, &mut cursor, 64)?.try_into().unwrap();
            let new_key_proof = take(bytes, &mut cursor, 64)?.try_into().unwrap();
            IdentityOperation::Rotate(KeyRotation {
                old_did, new_did, effective_at: timestamp, old_key_signature, new_key_proof,
            })
        }
        3 => {
            let did = take_string(bytes, &mut cursor)?;
            let signature = take(bytes, &mut cursor, 64)?.try_into().unwrap();
            IdentityOperation::Revoke { did, revoked_at: timestamp, signature }
        }
        _ => return Err(StorageError::CorruptLog),
    };
    if cursor != bytes.len() { return Err(StorageError::CorruptLog); }
    Ok(operation)
}

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), StorageError> {
    let length = u16::try_from(value.len()).map_err(|_| StorageError::RecordTooLarge)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn take_string(bytes: &[u8], cursor: &mut usize) -> Result<String, StorageError> {
    let length = u16::from_be_bytes(take(bytes, cursor, 2)?.try_into().unwrap()) as usize;
    String::from_utf8(take(bytes, cursor, length)?.to_vec()).map_err(|_| StorageError::CorruptLog)
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], StorageError> {
    let end = cursor.checked_add(length).ok_or(StorageError::CorruptLog)?;
    let value = bytes.get(*cursor..end).ok_or(StorageError::CorruptLog)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};

    fn temp_path() -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("qorvynt-web4-identity-{nonce}.log"))
    }

    #[test]
    fn file_log_survives_restart_and_replays_verified_identity() {
        let path = temp_path();
        let signer = SigningKey::from_bytes(&[61; 32]);
        let key = IdentityKey::from_public_key(signer.verifying_key().to_bytes()).unwrap();
        let payload = IdentityResolver::registration_payload(key.did(), 100);
        let proof = signer.sign(&IdentityKey::signature_payload(&payload)).to_bytes();
        {
            let mut persistent = PersistentIdentityResolver::open(FileIdentityLog::open(&path)).unwrap();
            persistent.register(key.clone(), 100, &proof).unwrap();
            assert!(persistent.resolver().resolve(key.did(), 100).is_some());
        }
        {
            let persistent = PersistentIdentityResolver::open(FileIdentityLog::open(&path)).unwrap();
            assert!(persistent.resolver().resolve(key.did(), 100).is_some());
            assert_eq!(persistent.resolver().events().len(), 1);
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_truncated_log_instead_of_silently_dropping_tail() {
        let path = temp_path();
        fs::write(&path, [0, 0, 0, 8, 1, 2]).unwrap();
        let result = PersistentIdentityResolver::open(FileIdentityLog::open(&path));
        assert!(matches!(result, Err(StorageError::CorruptLog)));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_signature_is_not_written_to_disk() {
        let path = temp_path();
        let signer = SigningKey::from_bytes(&[62; 32]);
        let key = IdentityKey::from_public_key(signer.verifying_key().to_bytes()).unwrap();
        let mut persistent = PersistentIdentityResolver::open(FileIdentityLog::open(&path)).unwrap();
        assert!(persistent.register(key, 10, &[0; 64]).is_err());
        assert!(!path.exists());
    }
}
