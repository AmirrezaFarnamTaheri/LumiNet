//
// IntroductionPointSet implements breadth-first round-robin rotation
// across backend instances. onionbalance's `get_intro_point` uses
// `zip_longest(*self.available_intro_points)` so IPs are drawn from
// each instance in turn before any instance repeats:
//
//   Instance A: [a1, a2]
//   Instance B: [b1]
//   Yield order: a1, b1, a2, a1, b1, a2, ...
//
// This maximizes backend diversity per descriptor and prevents
// correlation attacks that target a single backend instance.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroductionPoint {
    pub instance_id: u32,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Error)]
pub enum IntroPointError {
    #[error("no introduction points available")]
    Empty,
}

/// IntroductionPointSet rotates intro points round-robin across instances.
#[derive(Debug, Default)]
pub struct IntroductionPointSet {
    per_instance: Vec<Vec<IntroductionPoint>>,
    cursor: usize,
}

impl IntroductionPointSet {
    pub fn new() -> Self {
        Self {
            per_instance: Vec::new(),
            cursor: 0,
        }
    }

    /// Add an instance's intro points. Instance IDs need not be contiguous.
    pub fn add_instance(&mut self, instance_id: u32, points: Vec<IntroductionPoint>) {
        self.per_instance.push(points);
        let _ = instance_id; // stored implicitly by insertion order
    }

    /// Number of instances registered.
    pub fn instance_count(&self) -> usize {
        self.per_instance.len()
    }

    /// Total intro points across all instances.
    pub fn total_points(&self) -> usize {
        self.per_instance.iter().map(|v| v.len()).sum()
    }

    /// Yield intro points in round-robin order across instances. Never
    /// repeats an instance consecutively when other instances have points.
    pub fn iter_round_robin(&self) -> RoundRobinIter<'_> {
        RoundRobinIter {
            set: self,
            instance_idx: 0,
            instance_cursors: vec![0usize; self.per_instance.len()],
        }
    }

    /// Get the next intro point, cycling forever.
    pub fn next_point(&mut self) -> Result<IntroductionPoint, IntroPointError> {
        if self.per_instance.is_empty() {
            return Err(IntroPointError::Empty);
        }
        let total = self.total_points();
        if total == 0 {
            return Err(IntroPointError::Empty);
        }
        let instance_count = self.per_instance.len();
        let mut tried = 0usize;
        loop {
            let instance_idx = self.cursor % instance_count;
            self.cursor += 1;
            let instance = &self.per_instance[instance_idx];
            if instance.is_empty() {
                tried += 1;
                if tried >= instance_count {
                    return Err(IntroPointError::Empty);
                }
                continue;
            }
            // Simple round-robin within the instance.
            let pos = self.cursor % instance.len();
            return Ok(instance[pos].clone());
        }
    }
}

/// Iterator that yields intro points round-robin across instances.
pub struct RoundRobinIter<'a> {
    set: &'a IntroductionPointSet,
    instance_idx: usize,
    instance_cursors: Vec<usize>,
}

impl<'a> Iterator for RoundRobinIter<'a> {
    type Item = IntroductionPoint;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.set.per_instance.len();
        if n == 0 {
            return None;
        }
        for _ in 0..n {
            let idx = self.instance_idx % n;
            self.instance_idx += 1;
            let instance = &self.set.per_instance[idx];
            let cursor = &mut self.instance_cursors[idx];
            if *cursor < instance.len() {
                let point = instance[*cursor].clone();
                *cursor += 1;
                return Some(point);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let total: usize = self.set.per_instance.iter().map(|v| v.len()).sum();
        (total, Some(total))
    }
}

impl<'a> ExactSizeIterator for RoundRobinIter<'a> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_point(instance: u32, label: &str) -> IntroductionPoint {
        IntroductionPoint {
            instance_id: instance,
            address: format!("{label}.onion"),
            port: 443,
        }
    }

    #[test]
    fn round_robin_interleaves_instances() {
        let mut set = IntroductionPointSet::new();
        set.add_instance(0, vec![make_point(0, "a1"), make_point(0, "a2")]);
        set.add_instance(1, vec![make_point(1, "b1")]);
        let collected: Vec<_> = set.iter_round_robin().collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].address, "a1.onion");
        assert_eq!(collected[1].address, "b1.onion");
        assert_eq!(collected[2].address, "a2.onion");
    }

    #[test]
    fn empty_set_returns_error() {
        let mut set = IntroductionPointSet::new();
        assert!(matches!(set.next_point(), Err(IntroPointError::Empty)));
    }

    #[test]
    fn next_cycles_forever() {
        let mut set = IntroductionPointSet::new();
        set.add_instance(0, vec![make_point(0, "only")]);
        let a = set.next_point().unwrap();
        let b = set.next_point().unwrap();
        assert_eq!(a.address, "only.onion");
        assert_eq!(b.address, "only.onion");
    }
}
