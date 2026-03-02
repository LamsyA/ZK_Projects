use sha2::{Digest, Sha256};

/// Represents a Merkle Tree that supports:
/// - Adding data sequentially (0 -> n)
/// - Updating any leaf
/// - Getting the root hash
/// - Generating and verifying proofs
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All nodes in the tree stored in a flat array
    /// Index 0 is unused, root is at index 1
    /// For a node at index i: left child = 2*i, right child = 2*i + 1
    nodes: Vec<[u8; 32]>,
    /// Number of leaves (must be power of 2)
    leaf_count: usize,
    /// Number of leaves currently populated with actual data
    populated_count: usize,
}

/// Represents a proof for a leaf in the Merkle tree
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf index this proof is for
    pub leaf_index: usize,
    /// The sibling hashes along the path from leaf to root
    /// Each entry is (hash, is_left) where is_left indicates if the sibling is on the left
    pub siblings: Vec<([u8; 32], bool)>,
}

impl MerkleTree {
    /// Creates a new Merkle tree with capacity for `size` leaves
    /// Size must be a power of 2
    pub fn new(size: usize) -> Result<Self, &'static str> {
        if size == 0 {
            return Err("Size must be greater than 0");
        }
        if !size.is_power_of_two() {
            return Err("Size must be a power of 2");
        }

        // Total nodes = 2 * leaf_count - 1, but we use 1-based indexing
        // So we need 2 * leaf_count slots (index 0 unused)
        let total_nodes = 2 * size;
        let nodes = vec![[0u8; 32]; total_nodes];

        Ok(MerkleTree {
            nodes,
            leaf_count: size,
            populated_count: 0,
        })
    }

    /// Hash function using SHA-256
    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Hash two child nodes together
    fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(left);
        combined.extend_from_slice(right);
        Self::hash(&combined)
    }

    /// Get the index in the nodes array for a leaf at position `leaf_index`
    /// Leaves are stored in the second half of the array
    fn leaf_node_index(&self, leaf_index: usize) -> usize {
        self.leaf_count + leaf_index
    }

    /// Add data to the next available leaf position
    /// Data is added sequentially from index 0 to n-1
    pub fn add(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        if self.populated_count >= self.leaf_count {
            return Err("Tree is full");
        }

        let leaf_index = self.populated_count;
        let node_index = self.leaf_node_index(leaf_index);

        // Hash the data and store at leaf position
        self.nodes[node_index] = Self::hash(data);
        self.populated_count += 1;

        // Update the path from this leaf to the root
        self.update_path(node_index);

        Ok(leaf_index)
    }

    /// Update a specific leaf with new data
    pub fn update(&mut self, leaf_index: usize, data: &[u8]) -> Result<(), &'static str> {
        if leaf_index >= self.populated_count {
            return Err("Leaf index out of bounds or not yet populated");
        }

        let node_index = self.leaf_node_index(leaf_index);
        self.nodes[node_index] = Self::hash(data);

        // Update the path from this leaf to the root
        self.update_path(node_index);

        Ok(())
    }

    /// Update all nodes on the path from a given node to the root
    fn update_path(&mut self, mut node_index: usize) {
        while node_index > 1 {
            let parent_index = node_index / 2;
            let left_child = parent_index * 2;
            let right_child = parent_index * 2 + 1;

            self.nodes[parent_index] =
                Self::hash_nodes(&self.nodes[left_child], &self.nodes[right_child]);

            node_index = parent_index;
        }
    }

    /// Get the root hash of the tree
    pub fn root(&self) -> [u8; 32] {
        if self.populated_count == 0 {
            return [0u8; 32];
        }
        self.nodes[1]
    }

    /// Get the root hash as a hexadecimal string
    pub fn root_hex(&self) -> String {
        hex_encode(&self.root())
    }

    /// Generate a proof for a specific leaf
    pub fn proof(&self, leaf_index: usize) -> Result<MerkleProof, &'static str> {
        if leaf_index >= self.populated_count {
            return Err("Leaf index out of bounds or not yet populated");
        }

        let mut siblings = Vec::new();
        let mut node_index = self.leaf_node_index(leaf_index);

        while node_index > 1 {
            let sibling_index = if node_index % 2 == 0 {
                node_index + 1 // Current is left child, sibling is right
            } else {
                node_index - 1 // Current is right child, sibling is left
            };

            let is_left = node_index % 2 == 1; // Sibling is on left if current is right child
            siblings.push((self.nodes[sibling_index], is_left));

            node_index /= 2;
        }

        Ok(MerkleProof {
            leaf_index,
            siblings,
        })
    }

    /// Verify a proof against the current root
    pub fn verify(&self, data: &[u8], proof: &MerkleProof) -> bool {
        Self::verify_proof(data, proof, &self.root())
    }

    /// Static method to verify a proof against a given root
    pub fn verify_proof(data: &[u8], proof: &MerkleProof, root: &[u8; 32]) -> bool {
        let mut current_hash = Self::hash(data);

        for (sibling_hash, is_left) in &proof.siblings {
            current_hash = if *is_left {
                Self::hash_nodes(sibling_hash, &current_hash)
            } else {
                Self::hash_nodes(&current_hash, sibling_hash)
            };
        }

        current_hash == *root
    }

    /// Get the hash of a specific leaf
    pub fn get_leaf_hash(&self, leaf_index: usize) -> Result<[u8; 32], &'static str> {
        if leaf_index >= self.populated_count {
            return Err("Leaf index out of bounds or not yet populated");
        }
        Ok(self.nodes[self.leaf_node_index(leaf_index)])
    }

    /// Get the number of populated leaves
    pub fn len(&self) -> usize {
        self.populated_count
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.populated_count == 0
    }

    /// Get the total capacity of the tree
    pub fn capacity(&self) -> usize {
        self.leaf_count
    }

    /// Check if the tree is full
    pub fn is_full(&self) -> bool {
        self.populated_count == self.leaf_count
    }
}

impl MerkleProof {
    /// Convert the proof to a human-readable format
    pub fn to_hex_strings(&self) -> Vec<(String, bool)> {
        self.siblings
            .iter()
            .map(|(hash, is_left)| (hex_encode(hash), *is_left))
            .collect()
    }
}

/// Helper function to encode bytes as hexadecimal string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_tree() {
        let tree = MerkleTree::new(4).unwrap();
        assert_eq!(tree.capacity(), 4);
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_invalid_size() {
        assert!(MerkleTree::new(0).is_err());
        assert!(MerkleTree::new(3).is_err());
        assert!(MerkleTree::new(5).is_err());
    }

    #[test]
    fn test_add_data() {
        let mut tree = MerkleTree::new(4).unwrap();

        assert_eq!(tree.add(b"data0").unwrap(), 0);
        assert_eq!(tree.add(b"data1").unwrap(), 1);
        assert_eq!(tree.add(b"data2").unwrap(), 2);
        assert_eq!(tree.add(b"data3").unwrap(), 3);

        assert_eq!(tree.len(), 4);
        assert!(tree.is_full());
        assert!(tree.add(b"data4").is_err());
    }

    #[test]
    fn test_root_changes_on_add() {
        let mut tree = MerkleTree::new(4).unwrap();

        let empty_root = tree.root();
        tree.add(b"data0").unwrap();
        let root1 = tree.root();
        tree.add(b"data1").unwrap();
        let root2 = tree.root();

        assert_ne!(empty_root, root1);
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_update_leaf() {
        let mut tree = MerkleTree::new(4).unwrap();

        tree.add(b"data0").unwrap();
        tree.add(b"data1").unwrap();
        tree.add(b"data2").unwrap();
        tree.add(b"data3").unwrap();

        let root_before = tree.root();
        tree.update(1, b"new_data1").unwrap();
        let root_after = tree.root();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_proof_and_verify() {
        let mut tree = MerkleTree::new(4).unwrap();

        tree.add(b"data0").unwrap();
        tree.add(b"data1").unwrap();
        tree.add(b"data2").unwrap();
        tree.add(b"data3").unwrap();

        // Test proof for each leaf
        for i in 0..4 {
            let data = format!("data{}", i);
            let proof = tree.proof(i).unwrap();
            assert!(tree.verify(data.as_bytes(), &proof));
        }
    }

    #[test]
    fn test_proof_fails_with_wrong_data() {
        let mut tree = MerkleTree::new(4).unwrap();

        tree.add(b"data0").unwrap();
        tree.add(b"data1").unwrap();
        tree.add(b"data2").unwrap();
        tree.add(b"data3").unwrap();

        let proof = tree.proof(0).unwrap();
        assert!(!tree.verify(b"wrong_data", &proof));
    }

    #[test]
    fn test_proof_after_update() {
        let mut tree = MerkleTree::new(4).unwrap();

        tree.add(b"data0").unwrap();
        tree.add(b"data1").unwrap();
        tree.add(b"data2").unwrap();
        tree.add(b"data3").unwrap();

        // Update leaf 1
        tree.update(1, b"new_data1").unwrap();

        // Old proof should fail
        let proof = tree.proof(1).unwrap();
        assert!(!tree.verify(b"data1", &proof));

        // New proof should work
        assert!(tree.verify(b"new_data1", &proof));
    }

    #[test]
    fn test_static_verify() {
        let mut tree = MerkleTree::new(4).unwrap();

        tree.add(b"data0").unwrap();
        tree.add(b"data1").unwrap();
        tree.add(b"data2").unwrap();
        tree.add(b"data3").unwrap();

        let root = tree.root();
        let proof = tree.proof(2).unwrap();

        // Verify using static method
        assert!(MerkleTree::verify_proof(b"data2", &proof, &root));
        assert!(!MerkleTree::verify_proof(b"wrong", &proof, &root));
    }

    #[test]
    fn test_large_tree() {
        let mut tree = MerkleTree::new(16).unwrap();

        for i in 0..16 {
            let data = format!("data{}", i);
            tree.add(data.as_bytes()).unwrap();
        }

        // Verify all proofs
        for i in 0..16 {
            let data = format!("data{}", i);
            let proof = tree.proof(i).unwrap();
            assert!(tree.verify(data.as_bytes(), &proof));
            assert_eq!(proof.siblings.len(), 4); // log2(16) = 4
        }
    }

    #[test]
    fn test_single_leaf_tree() {
        let mut tree = MerkleTree::new(1).unwrap();

        tree.add(b"only_data").unwrap();

        let proof = tree.proof(0).unwrap();
        assert!(tree.verify(b"only_data", &proof));
        assert_eq!(proof.siblings.len(), 0);
    }

    #[test]
    fn test_two_leaf_tree() {
        let mut tree = MerkleTree::new(2).unwrap();

        tree.add(b"left").unwrap();
        tree.add(b"right").unwrap();

        let proof0 = tree.proof(0).unwrap();
        let proof1 = tree.proof(1).unwrap();

        assert!(tree.verify(b"left", &proof0));
        assert!(tree.verify(b"right", &proof1));
        assert_eq!(proof0.siblings.len(), 1);
        assert_eq!(proof1.siblings.len(), 1);
    }

    #[test]
    fn test_hex_output() {
        let mut tree = MerkleTree::new(4).unwrap();

        tree.add(b"data0").unwrap();
        tree.add(b"data1").unwrap();
        tree.add(b"data2").unwrap();
        tree.add(b"data3").unwrap();

        let root_hex = tree.root_hex();
        assert_eq!(root_hex.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars

        let proof = tree.proof(0).unwrap();
        let hex_proof = proof.to_hex_strings();
        assert_eq!(hex_proof.len(), 2); // log2(4) = 2
    }
}
