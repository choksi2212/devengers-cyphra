// Custom GBDT inference engine (no external runtime)

use serde::{Deserialize, Serialize};

/// GBDT ensemble
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ensemble {
    pub trees: Vec<Tree>,
    pub weights: Vec<f32>,
}

/// Decision tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tree {
    pub nodes: Vec<Node>,
    pub leaves: Vec<f32>,
}

/// Tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub feature_idx: usize,
    pub threshold: f32,
    pub left_child: usize,
    pub right_child: usize,
    pub is_leaf: bool,
}

impl Ensemble {
    /// Predict using ensemble
    pub fn predict(&self, features: &[f32]) -> f32 {
        self.trees
            .iter()
            .zip(&self.weights)
            .map(|(tree, weight)| weight * tree.predict(features))
            .sum()
    }
    
    /// Load ensemble from JSON file
    pub fn load_from_json(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = std::fs::read_to_string(path)?;
        let ensemble: Self = serde_json::from_str(&data)?;
        Ok(ensemble)
    }
    
    /// Save ensemble to JSON file
    pub fn save_to_json(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }
}

impl Tree {
    /// Predict using single tree
    pub fn predict(&self, features: &[f32]) -> f32 {
        let mut node_idx = 0;
        
        loop {
            let node = &self.nodes[node_idx];
            
            if node.is_leaf {
                return self.leaves[node_idx];
            }
            
            if features[node.feature_idx] <= node.threshold {
                node_idx = node.left_child;
            } else {
                node_idx = node.right_child;
            }
        }
    }
}

impl Default for Ensemble {
    fn default() -> Self {
        // Placeholder ensemble
        Self {
            trees: vec![],
            weights: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_prediction() {
        let tree = Tree {
            nodes: vec![
                Node {
                    feature_idx: 0,
                    threshold: 0.5,
                    left_child: 1,
                    right_child: 2,
                    is_leaf: false,
                },
                Node {
                    feature_idx: 0,
                    threshold: 0.0,
                    left_child: 0,
                    right_child: 0,
                    is_leaf: true,
                },
                Node {
                    feature_idx: 0,
                    threshold: 0.0,
                    left_child: 0,
                    right_child: 0,
                    is_leaf: true,
                },
            ],
            leaves: vec![0.0, 0.3, 0.8],
        };
        
        let features = vec![0.2];
        let prediction = tree.predict(&features);
        assert_eq!(prediction, 0.3);
    }
}
