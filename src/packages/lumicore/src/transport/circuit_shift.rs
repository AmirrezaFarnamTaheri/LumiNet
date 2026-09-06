
use std::collections::VecDeque;
use std::ops::Sub;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TimeUnit {
    Day,
    Week,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourcePosition {
    Client,
    Exit,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DestinationPosition {
    ISP,
    Entry,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
    Padding,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelayCommand {
    Begin,
    Connected,
    Data,
    Sendme,
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cell {
    pub time: f64,
    pub direction: Direction,
    pub relay_cmd: RelayCommand,
}

// Implement ordering for cells based on time, matching gtt23/cellshift behavior.
impl Eq for Cell {}

impl PartialOrd for Cell {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Cell {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.time
            .partial_cmp(&other.time)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

#[derive(Debug, Clone)]
pub struct Circuit {
    pub uuid: String,
    pub len: usize,
    pub cells: Vec<Cell>,
}

pub fn round_micro_res(time: f64) -> f64 {
    (time * 1_000_000.0).round() / 1_000_000.0
}

#[derive(Debug, Clone, PartialEq)]
pub struct TimeEstimate {
    pub time: f64,
    pub cell_index: usize,
}

impl TimeEstimate {
    pub fn new(time: f64, cell_index: usize) -> Self {
        Self { time, cell_index }
    }
}

struct PartialRttEstimate {
    begin: f64,
}

impl PartialRttEstimate {
    fn new(begin: f64) -> Self {
        Self { begin }
    }

    fn into_rtt_estimate(self, end: f64, cell_index: usize) -> TimeEstimate {
        let rtt = round_micro_res(end - self.begin);
        TimeEstimate::new(rtt, cell_index)
    }
}

struct CellTimingMeasurements {
    first_connected: Option<PartialRttEstimate>,
    primary_rtt: Option<TimeEstimate>,
    num_data_sent: usize,
    sendme_triggers: VecDeque<PartialRttEstimate>,
    updated_rtts: VecDeque<TimeEstimate>,
    use_sendme_estimates: bool,
}

impl CellTimingMeasurements {
    fn new() -> Self {
        Self {
            first_connected: None,
            primary_rtt: None,
            num_data_sent: 0,
            sendme_triggers: VecDeque::new(),
            updated_rtts: VecDeque::new(),
            use_sendme_estimates: true,
        }
    }

    fn estimate_rtts(mut self, trace: &[Cell], position: SourcePosition) -> VecDeque<TimeEstimate> {
        if position != SourcePosition::Exit {
            // As noted in gtt23/cellshift, client-side RTT estimation is not fully specified.
            // Return empty or fallback.
            return VecDeque::new();
        }

        for (i, cell) in trace.iter().enumerate() {
            match cell.direction {
                Direction::ServerToClient => {
                    if cell.relay_cmd == RelayCommand::Connected {
                        self.sent_connected(cell.time, i);
                    } else if cell.relay_cmd == RelayCommand::Data {
                        self.sent_data(cell.time, i);
                    }
                }
                Direction::ClientToServer => {
                    if cell.relay_cmd == RelayCommand::Data {
                        self.received_data(cell.time, i);
                    } else if cell.relay_cmd == RelayCommand::Sendme {
                        self.received_sendme(cell.time, i);
                    }
                }
                Direction::Padding => {}
            }
        }

        self.into_rtt_estimates()
    }

    fn sent_connected(&mut self, cell_time: f64, _cell_index: usize) {
        if self.primary_rtt.is_none() && self.first_connected.is_none() {
            self.first_connected = Some(PartialRttEstimate::new(cell_time));
        }
    }

    fn received_data(&mut self, cell_time: f64, cell_index: usize) {
        if self.primary_rtt.is_none() {
            if let Some(partial) = self.first_connected.take() {
                self.primary_rtt = Some(partial.into_rtt_estimate(cell_time, cell_index));
            }
        }
    }

    fn sent_data(&mut self, cell_time: f64, _cell_index: usize) {
        self.num_data_sent += 1;
        if self.num_data_sent.is_multiple_of(31) {
            self.sendme_triggers
                .push_back(PartialRttEstimate::new(cell_time));
        }
    }

    fn received_sendme(&mut self, cell_time: f64, cell_index: usize) {
        if let Some(partial) = self.sendme_triggers.pop_front() {
            self.updated_rtts
                .push_back(partial.into_rtt_estimate(cell_time, cell_index));
        } else {
            self.use_sendme_estimates = false;
        }
    }

    fn into_rtt_estimates(mut self) -> VecDeque<TimeEstimate> {
        let mut rtts = if self.use_sendme_estimates {
            self.updated_rtts
        } else {
            VecDeque::new()
        };

        if let Some(estimate) = self.primary_rtt.take() {
            rtts.push_front(estimate);
        }

        rtts
    }
}

#[derive(Clone)]
pub struct RttEstimator {
    position: SourcePosition,
    rtts: Vec<TimeEstimate>,
    rtt_min: Option<f64>,
    len_cells: usize,
}

impl RttEstimator {
    pub fn new(trace: &[Cell], position: SourcePosition) -> Self {
        let mut estimator = Self {
            rtts: Vec::new(),
            rtt_min: None,
            len_cells: trace.len(),
            position,
        };

        let mut rtts = CellTimingMeasurements::new().estimate_rtts(trace, position);
        estimator.rtts.reserve_exact(rtts.len());

        while let Some(estimate) = rtts.pop_front() {
            let rtt_min = estimator.rtt_min.get_or_insert(estimate.time);
            *rtt_min = rtt_min.min(estimate.time);
            estimator.rtts.push(estimate);
        }

        // If no RTT estimates were computed, fallback to a mock propagation delay estimation if trace has Begin/Connected
        if estimator.rtt_min.is_none() && trace.len() >= 2 {
            // Find first Begin and Connected
            let mut begin_time = None;
            let mut connected_time = None;
            for cell in trace {
                if cell.relay_cmd == RelayCommand::Begin {
                    begin_time = Some(cell.time);
                } else if cell.relay_cmd == RelayCommand::Connected {
                    connected_time = Some(cell.time);
                }
            }
            if let (Some(b), Some(c)) = (begin_time, connected_time) {
                if c > b {
                    estimator.rtt_min = Some(round_micro_res(c - b));
                }
            }
        }

        estimator
    }

    pub fn position(&self) -> SourcePosition {
        self.position
    }

    pub fn propagation_delay(&self) -> Option<f64> {
        self.rtt_min
    }

    pub fn len_cells(&self) -> usize {
        self.len_cells
    }

    pub fn iter_rtts(&self) -> TimeEstimateIterator<'_> {
        TimeEstimateIterator::new(self, false)
    }

    pub fn iter_congestion(&self) -> TimeEstimateIterator<'_> {
        TimeEstimateIterator::new(self, true)
    }
}

pub struct TimeEstimateIterator<'a> {
    estimator: &'a RttEstimator,
    estimate_index: usize,
    cell_index: usize,
    is_congestion: bool,
}

impl<'a> TimeEstimateIterator<'a> {
    fn new(estimator: &'a RttEstimator, is_congestion: bool) -> Self {
        Self {
            estimator,
            estimate_index: 0,
            cell_index: 0,
            is_congestion,
        }
    }
}

impl<'a> Iterator for TimeEstimateIterator<'a> {
    type Item = TimeEstimate;

    fn next(&mut self) -> Option<Self::Item> {
        let has_estimate = self.estimate_index < self.estimator.rtts.len();
        let is_last = has_estimate && self.estimate_index == self.estimator.rtts.len() - 1;

        if has_estimate {
            let est = &self.estimator.rtts[self.estimate_index];

            if (self.cell_index <= est.cell_index)
                || (is_last && self.cell_index < self.estimator.len_cells())
            {
                self.cell_index += 1;

                let mut est = est.clone();
                if self.is_congestion {
                    est.time = est
                        .time
                        .sub(self.estimator.propagation_delay().unwrap_or_default())
                }

                Some(est)
            } else {
                self.estimate_index += 1;
                self.next()
            }
        } else {
            // If no RTT estimates, but we have a fallback propagation delay, produce a constant estimate
            if self.estimator.rtts.is_empty() && self.cell_index < self.estimator.len_cells() {
                self.cell_index += 1;
                let t = self.estimator.propagation_delay().unwrap_or_default();
                Some(TimeEstimate::new(
                    if self.is_congestion { 0.0 } else { t },
                    self.cell_index - 1,
                ))
            } else {
                None
            }
        }
    }
}

pub struct CellShift<'a> {
    shifted: Circuit,
    estimator: &'a RttEstimator,
    prev_time_inward: f64,
    prev_time_outward: f64,
}

impl<'a> CellShift<'a> {
    pub fn new(circuit: &Circuit, estimator: &'a RttEstimator) -> Self {
        Self {
            estimator,
            shifted: circuit.clone(),
            prev_time_inward: 0.0,
            prev_time_outward: 0.0,
        }
    }

    pub fn shift(
        mut self,
        dst_pos: DestinationPosition,
        dst_estimator: &RttEstimator,
        dst_prop_delay: f64,
    ) -> Result<Circuit, String> {
        let src_delay = self
            .estimator
            .propagation_delay()
            .ok_or("Source propagation delay estimate is not available.")?;
        let _dst_delay = dst_estimator
            .propagation_delay()
            .ok_or("Destination propagation delay estimate is not available.")?;

        let mut rtt_iter = self.estimator.iter_rtts();
        let mut dst_cong_cycle = dst_estimator.iter_congestion().collect::<Vec<_>>();
        if dst_cong_cycle.is_empty() {
            // Fallback default congestion
            dst_cong_cycle.push(TimeEstimate::new(0.0, 0));
        }
        for (dst_idx, i) in (0..self.shifted.cells.len()).enumerate() {
            let src_est = rtt_iter
                .next()
                .unwrap_or_else(|| TimeEstimate::new(src_delay, i));
            let dst_est = &dst_cong_cycle[dst_idx % dst_cong_cycle.len()];
            let src_rtt = src_est.time;
            let dst_cong = dst_est.time;
            let dst_rtt = dst_prop_delay + dst_cong;

            self.shift_cell_time(i, self.estimator.position(), src_rtt, dst_pos, dst_rtt)?;
        }

        // Sort cells to realign client/server streams
        self.shifted.cells.sort();

        Ok(self.shifted)
    }

    fn shift_cell_time(
        &mut self,
        cell_index: usize,
        src_pos: SourcePosition,
        src_rtt: f64,
        dst_pos: DestinationPosition,
        dst_rtt: f64,
    ) -> Result<(), String> {
        let cell = &self.shifted.cells[cell_index];
        let cell_direction = cell.direction;
        let cell_time = cell.time;

        let shifted_time = match cell_direction {
            Direction::ServerToClient => match src_pos {
                SourcePosition::Client => match dst_pos {
                    DestinationPosition::ISP => {
                        cell_time - latency(src_rtt, 3.0) + latency(dst_rtt, 2.5)
                    }
                    DestinationPosition::Entry => {
                        cell_time - latency(src_rtt, 3.0) + latency(dst_rtt, 2.0)
                    }
                },
                SourcePosition::Exit => match dst_pos {
                    DestinationPosition::ISP => cell_time + latency(dst_rtt, 2.5),
                    DestinationPosition::Entry => cell_time + latency(dst_rtt, 2.0),
                },
            },
            Direction::ClientToServer => match src_pos {
                SourcePosition::Client => match dst_pos {
                    DestinationPosition::ISP => cell_time + latency(dst_rtt, 0.5),
                    DestinationPosition::Entry => cell_time + latency(dst_rtt, 1.0),
                },
                SourcePosition::Exit => match dst_pos {
                    DestinationPosition::ISP => {
                        cell_time - latency(src_rtt, 3.0) + latency(dst_rtt, 0.5)
                    }
                    DestinationPosition::Entry => {
                        cell_time - latency(src_rtt, 3.0) + latency(dst_rtt, 1.0)
                    }
                },
            },
            Direction::Padding => {
                return Err("Unexpected padding cell".to_string());
            }
        };

        let shifted_time = match cell_direction {
            Direction::ClientToServer => self.next_outward_time(shifted_time),
            Direction::ServerToClient => self.next_inward_time(shifted_time),
            Direction::Padding => shifted_time,
        };

        if shifted_time < 0.000001 {
            return Err(format!("Shifted cell time is < 1 micro ({})", shifted_time));
        }

        self.shifted.cells[cell_index].time = shifted_time;
        Ok(())
    }

    fn next_inward_time(&mut self, time: f64) -> f64 {
        let new_time = round_micro_res(time)
            .max(0.000001)
            .max(self.prev_time_inward);
        self.prev_time_inward = new_time;
        new_time
    }

    fn next_outward_time(&mut self, time: f64) -> f64 {
        let new_time = round_micro_res(time)
            .max(0.000001)
            .max(self.prev_time_outward);
        self.prev_time_outward = new_time;
        new_time
    }
}

fn latency(rtt: f64, num_hops: f64) -> f64 {
    rtt / 6.0 * num_hops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shift_basic() {
        let rtt = 0.6;
        let cells = vec![
            Cell {
                time: 0.000001,
                direction: Direction::ServerToClient,
                relay_cmd: RelayCommand::Connected,
            },
            Cell {
                time: 0.600001,
                direction: Direction::ClientToServer,
                relay_cmd: RelayCommand::Data,
            },
        ];

        let circ = Circuit {
            uuid: "test-uuid".to_string(),
            len: 2,
            cells,
        };

        let est = RttEstimator::new(&circ.cells, SourcePosition::Exit);
        assert_eq!(est.propagation_delay(), Some(0.6));

        let cell_shift = CellShift::new(&circ, &est);
        let shifted_circ = cell_shift
            .shift(DestinationPosition::Entry, &est, rtt)
            .unwrap();

        assert_eq!(shifted_circ.cells[0].direction, Direction::ServerToClient);
        assert_eq!(shifted_circ.cells[0].time, 0.200001);
    }
}
