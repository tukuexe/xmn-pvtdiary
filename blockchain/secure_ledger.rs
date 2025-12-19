//! Secure Blockchain Ledger for Diary Audit Trails
//! Provides immutable, timestamped audit logs for all security events

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use ring::signature::{self, KeyPair, Ed25519KeyPair};

type Hash = [u8; 32];
type Timestamp = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub event_type: EventType,
    pub user_id: Option<String>,
    pub ip_address: String,
    pub location: Option<Location>,
    pub severity: SeverityLevel,
    pub description: String,
    pub metadata: serde_json::Value,
    pub timestamp: Timestamp,
    pub previous_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    LoginAttempt,
    PasswordChange,
    EntryCreation,
    EntryModification,
    SecurityBreach,
    LockdownTrigger,
    AdminAction,
    SystemAlert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy: f64,
    pub city: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub index: u64,
    pub events: Vec<SecurityEvent>,
    pub timestamp: Timestamp,
    pub previous_hash: Hash,
    pub hash: Hash,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

pub struct SecureLedger {
    chain: VecDeque<Block>,
    pending_events: Vec<SecurityEvent>,
    key_pair: Ed25519KeyPair,
    difficulty: u32,
}

impl SecureLedger {
    pub fn new() -> Result<Self, String> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| format!("Failed to generate key pair: {}", e))?;
        
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|e| format!("Failed to create key pair: {}", e))?;
        
        let mut ledger = SecureLedger {
            chain: VecDeque::new(),
            pending_events: Vec::new(),
            key_pair,
            difficulty: 4,
        };
        
        ledger.create_genesis_block()?;
        Ok(ledger)
    }
    
    fn create_genesis_block(&mut self) -> Result<(), String> {
        let timestamp = current_timestamp();
        let genesis_event = SecurityEvent {
            event_id: "genesis".to_string(),
            event_type: EventType::SystemAlert,
            user_id: None,
            ip_address: "0.0.0.0".to_string(),
            location: None,
            severity: SeverityLevel::Info,
            description: "Genesis block created".to_string(),
            metadata: serde_json::json!({"system": "initialized"}),
            timestamp,
            previous_hash: [0u8; 32],
        };
        
        let genesis_block = Block {
            index: 0,
            events: vec![genesis_event],
            timestamp,
            previous_hash: [0u8; 32],
            hash: [0u8; 32],
            nonce: 0,
            signature: Vec::new(),
        };
        
        let signed_block = self.sign_block(genesis_block)?;
        self.chain.push_back(signed_block);
        
        Ok(())
    }
    
    pub fn add_event(&mut self, event: SecurityEvent) -> Result<(), String> {
        // Validate event
        self.validate_event(&event)?;
        
        // Add to pending events
        self.pending_events.push(event);
        
        // Mine block if we have enough events
        if self.pending_events.len() >= 10 {
            self.mine_block()?;
        }
        
        Ok(())
    }
    
    fn validate_event(&self, event: &SecurityEvent) -> Result<(), String> {
        // Basic validation
        if event.event_id.is_empty() {
            return Err("Event ID cannot be empty".to_string());
        }
        
        if event.ip_address.is_empty() {
            return Err("IP address cannot be empty".to_string());
        }
        
        if event.description.is_empty() {
            return Err("Description cannot be empty".to_string());
        }
        
        // Timestamp validation (not in future)
        let current_time = current_timestamp();
        if event.timestamp > current_time + 300 { // 5 minutes tolerance
            return Err("Event timestamp is in the future".to_string());
        }
        
        Ok(())
    }
    
    fn mine_block(&mut self) -> Result<(), String> {
        let previous_block = self.chain.back()
            .ok_or("No previous block found")?;
        
        let mut block = Block {
            index: previous_block.index + 1,
            events: self.pending_events.drain(..).collect(),
            timestamp: current_timestamp(),
            previous_hash: previous_block.hash,
            hash: [0u8; 32],
            nonce: 0,
            signature: Vec::new(),
        };
        
        // Proof of Work
        self.proof_of_work(&mut block);
        
        // Sign the block
        let signed_block = self.sign_block(block)?;
        
        // Validate before adding
        self.validate_block(&signed_block)?;
        
        // Add to chain
        self.chain.push_back(signed_block);
        
        // Keep chain size manageable
        if self.chain.len() > 1000 {
            self.chain.pop_front();
        }
        
        Ok(())
    }
    
    fn proof_of_work(&self, block: &mut Block) {
        let target_prefix = vec![0u8; self.difficulty as usize];
        
        loop {
            let block_data = self.serialize_block_for_hashing(block);
            let mut hasher = Sha256::new();
            hasher.update(&block_data);
            let hash = hasher.finalize();
            
            if hash[..self.difficulty as usize] == target_prefix {
                block.hash = hash.into();
                break;
            }
            
            block.nonce += 1;
        }
    }
    
    fn sign_block(&self, mut block: Block) -> Result<Block, String> {
        let message = self.serialize_block_for_signing(&block);
        let signature = self.key_pair.sign(&message);
        
        block.signature = signature.as_ref().to_vec();
        Ok(block)
    }
    
    fn validate_block(&self, block: &Block) -> Result<(), String> {
        // Verify hash meets difficulty
        let target_prefix = vec![0u8; self.difficulty as usize];
        if block.hash[..self.difficulty as usize] != target_prefix {
            return Err("Block hash doesn't meet difficulty".to_string());
        }
        
        // Verify signature
        let message = self.serialize_block_for_signing(block);
        let public_key_bytes = self.key_pair.public_key().as_ref();
        let signature = &block.signature;
        
        signature::verify(
            &signature::ED25519,
            public_key_bytes,
            &message,
            signature,
        ).map_err(|e| format!("Invalid block signature: {}", e))?;
        
        // Verify events
        for event in &block.events {
            self.validate_event(event)?;
        }
        
        Ok(())
    }
    
    fn serialize_block_for_hashing(&self, block: &Block) -> Vec<u8> {
        let mut data = Vec::new();
        
        data.extend_from_slice(&block.index.to_be_bytes());
        data.extend_from_slice(&block.timestamp.to_be_bytes());
        data.extend_from_slice(&block.previous_hash);
        data.extend_from_slice(&block.nonce.to_be_bytes());
        
        for event in &block.events {
            let event_bytes = serde_json::to_vec(event).unwrap();
            data.extend_from_slice(&event_bytes);
        }
        
        data
    }
    
    fn serialize_block_for_signing(&self, block: &Block) -> Vec<u8> {
        let mut data = self.serialize_block_for_hashing(block);
        data.extend_from_slice(&block.hash);
        data
    }
    
    pub fn verify_chain(&self) -> Result<bool, String> {
        for i in 1..self.chain.len() {
            let previous = &self.chain[i - 1];
            let current = &self.chain[i];
            
            // Check hash linkage
            if current.previous_hash != previous.hash {
                return Err(format!("Chain broken at block {}", i));
            }
            
            // Validate block
            self.validate_block(current)?;
            
            // Check timestamp order
            if current.timestamp < previous.timestamp {
                return Err(format!("Block {} has earlier timestamp than previous", i));
            }
        }
        
        Ok(true)
    }
    
    pub fn get_audit_trail(&self, user_id: Option<&str>) -> Vec<&SecurityEvent> {
        let mut audit_trail = Vec::new();
        
        for block in &self.chain {
            for event in &block.events {
                match user_id {
                    Some(id) if event.user_id.as_deref() == Some(id) => {
                        audit_trail.push(event);
                    }
                    None => audit_trail.push(event),
                    _ => {}
                }
            }
        }
        
        audit_trail
    }
    
    pub fn search_events(&self, query: &str) -> Vec<&SecurityEvent> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();
        
        for block in &self.chain {
            for event in &block.events {
                if event.description.to_lowercase().contains(&query_lower) ||
                   event.event_id.to_lowercase().contains(&query_lower) ||
                   event.ip_address.contains(&query_lower) {
                    results.push(event);
                }
            }
        }
        
        results
    }
    
    pub fn get_statistics(&self) -> LedgerStatistics {
        let mut stats = LedgerStatistics {
            total_blocks: self.chain.len() as u64,
            total_events: 0,
            events_by_type: std::collections::HashMap::new(),
            events_by_severity: std::collections::HashMap::new(),
            last_update: 0,
        };
        
        for block in &self.chain {
            stats.total_events += block.events.len() as u64;
            stats.last_update = std::cmp::max(stats.last_update, block.timestamp);
            
            for event in &block.events {
                *stats.events_by_type.entry(format!("{:?}", event.event_type))
                    .or_insert(0) += 1;
                
                *stats.events_by_severity.entry(event.severity.clone())
                    .or_insert(0) += 1;
            }
        }
        
        stats
    }
    
    pub fn export_chain(&self, start_index: u64, end_index: u64) -> Result<Vec<Block>, String> {
        let mut exported = Vec::new();
        
        for block in &self.chain {
            if block.index >= start_index && block.index <= end_index {
                exported.push(block.clone());
            }
        }
        
        if exported.is_empty() {
            Err("No blocks in specified range".to_string())
        } else {
            Ok(exported)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LedgerStatistics {
    pub total_blocks: u64,
    pub total_events: u64,
    pub events_by_type: std::collections::HashMap<String, u64>,
    pub events_by_severity: std::collections::HashMap<SeverityLevel, u64>,
    pub last_update: Timestamp,
}

fn current_timestamp() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Merkle tree for efficient event verification
pub struct MerkleTree {
    root: Hash,
    leaves: Vec<Hash>,
}

impl MerkleTree {
    pub fn from_events(events: &[SecurityEvent]) -> Self {
        let mut leaves: Vec<Hash> = events.iter()
            .map(|event| {
                let data = serde_json::to_vec(event).unwrap();
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().into()
            })
            .collect();
        
        // Ensure even number of leaves
        if leaves.len() % 2 != 0 {
            leaves.push(leaves.last().unwrap().clone());
        }
        
        let root = Self::build_tree(&leaves);
        
        MerkleTree { root, leaves }
    }
    
    fn build_tree(leaves: &[Hash]) -> Hash {
        if leaves.len() == 1 {
            return leaves[0];
        }
        
        let mut next_level = Vec::new();
        for chunk in leaves.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            }
            next_level.push(hasher.finalize().into());
        }
        
        Self::build_tree(&next_level)
    }
    
    pub fn get_root(&self) -> Hash {
        self.root
    }
    
    pub fn verify_event(&self, event: &SecurityEvent, proof: &[Hash]) -> bool {
        let event_hash: Hash = {
            let data = serde_json::to_vec(event).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().into()
        };
        
        let mut current_hash = event_hash;
        for sibling in proof {
            let mut hasher = Sha256::new();
            if current_hash < *sibling {
                hasher.update(&current_hash);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current_hash);
            }
            current_hash = hasher.finalize().into();
        }
        
        current_hash == self.root
    }
}
