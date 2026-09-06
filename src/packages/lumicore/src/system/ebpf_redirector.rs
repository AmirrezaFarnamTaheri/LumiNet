// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.

//! # eBPF socket-redirect decision engine
//!
//! Userspace port of mitmproxy_rs's cgroup/sock-create interception program.
//! The production eBPF object (aya, `no_std`, cgroup/sock_create attach point)
//! binds matching sockets to the redirected interface by writing
//! `sock.bound_dev_if`; this module owns the *exact* include/exclude decision
//! semantics so the policy can be configured, simulated, and tested without a
//! loaded program, and so a future Linux loader can consume the same config.
//!
//! Semantics (mirroring upstream `should_intercept`):
//!
//! 1. The default verdict is `false` (do not intercept), **unless** the first
//!    configured action is an [`Action::Exclude`], which flips the mode to
//!    blacklist-style (intercept everything except the excluded commands).
//! 2. Every [`Action::Include`] whose matcher matches ORs the verdict to `true`.
//! 3. Every [`Action::Exclude`] whose matcher matches ANDs the verdict to `false`.
//! 4. The evaluation walks the configured action list in order and is bounded
//!    by [`MAX_ACTIONS`], matching the fixed-size `Array` map upstream.

/// Maximum number of actions carried in one interception config. Mirrors the
/// fixed-size eBPF `Array` map (`INTERCEPT_CONF_LEN`) upstream.
pub const MAX_ACTIONS: usize = 64;

/// Matches a socket-creating process by command line and/or pid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessMatcher {
    /// Command string starts with the given prefix.
    Prefix(String),
    /// Command string ends with the given suffix.
    Suffix(String),
    /// Command string contains the given substring.
    Contains(String),
    /// Command string is exactly equal.
    Exact(String),
    /// Process id falls inside the inclusive range.
    PidRange { min: u32, max: u32 },
    /// Matches every socket-creating process.
    All,
}

impl ProcessMatcher {
    /// Convenience constructor for [`ProcessMatcher::Prefix`].
    pub fn prefix(p: &str) -> Self {
        Self::Prefix(p.to_string())
    }

    /// Convenience constructor for [`ProcessMatcher::Suffix`].
    pub fn suffix(s: &str) -> Self {
        Self::Suffix(s.to_string())
    }

    /// Convenience constructor for [`ProcessMatcher::Contains`].
    pub fn contains(s: &str) -> Self {
        Self::Contains(s.to_string())
    }

    /// Convenience constructor for [`ProcessMatcher::Exact`].
    pub fn exact(e: &str) -> Self {
        Self::Exact(e.to_string())
    }

    /// Evaluate the matcher. A `None` command only matches [`ProcessMatcher::All`]
    /// and [`ProcessMatcher::PidRange`] (the kernel can always supply the pid).
    pub fn matches(&self, command: Option<&str>, pid: u32) -> bool {
        match self {
            ProcessMatcher::All => true,
            ProcessMatcher::PidRange { min, max } => pid >= *min && pid <= *max,
            ProcessMatcher::Prefix(p) => {
                command.is_some_and(|c| c.starts_with(p.as_str()))
            }
            ProcessMatcher::Suffix(s) => {
                command.is_some_and(|c| c.ends_with(s.as_str()))
            }
            ProcessMatcher::Contains(s) => command.is_some_and(|c| c.contains(s.as_str())),
            ProcessMatcher::Exact(e) => command.is_some_and(|c| c == e.as_str()),
        }
    }
}

/// One interception rule. Order in the config is significant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Add matching processes to the intercepted set.
    Include(ProcessMatcher),
    /// Remove matching processes from the intercepted set.
    Exclude(ProcessMatcher),
}

/// Interception policy: an ordered action list plus the interface index that
/// matching sockets must be bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptConf {
    actions: Vec<Action>,
    interface_id: u32,
}

/// Config validation failures.
#[derive(Debug, thiserror::Error)]
pub enum InterceptConfError {
    #[error("interception config exceeds the eBPF map capacity of {MAX_ACTIONS} actions")]
    TooManyActions,
}

impl InterceptConf {
    /// Build a config, validating the action count against the eBPF map size.
    pub fn new(actions: Vec<Action>, interface_id: u32) -> Result<Self, InterceptConfError> {
        if actions.len() > MAX_ACTIONS {
            return Err(InterceptConfError::TooManyActions);
        }
        Ok(Self {
            actions,
            interface_id,
        })
    }

    /// The ordered action list.
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// Interface index matching sockets are bound to.
    pub fn interface_id(&self) -> u32 {
        self.interface_id
    }

    /// Upstream decision algorithm. See the module documentation for the
    /// exact include/exclude semantics.
    pub fn should_intercept(&self, command: Option<&str>, pid: u32) -> bool {
        let mut intercept = matches!(self.actions.first(), Some(Action::Exclude(_)));
        for action in &self.actions {
            match action {
                Action::Include(pattern) => {
                    intercept = intercept || pattern.matches(command, pid);
                }
                Action::Exclude(pattern) => {
                    intercept = intercept && !pattern.matches(command, pid);
                }
            }
        }
        intercept
    }

    /// Bind decision for the cgroup/sock_create hook: `Some(interface_id)`
    /// when the socket must be redirected (upstream writes `sock.bound_dev_if`),
    /// `None` when the socket is left untouched.
    pub fn bind_interface(&self, command: Option<&str>, pid: u32) -> Option<u32> {
        if self.should_intercept(command, pid) {
            Some(self.interface_id)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(actions: Vec<Action>) -> InterceptConf {
        InterceptConf::new(actions, 7).expect("valid conf")
    }

    #[test]
    fn empty_config_intercepts_nothing() {
        assert!(!conf(Vec::new()).should_intercept(Some("/usr/bin/curl"), 100));
    }

    #[test]
    fn whitelist_mode_includes_only_matching_commands() {
        let c = conf(vec![Action::Include(ProcessMatcher::contains("curl"))]);
        assert!(c.should_intercept(Some("/usr/bin/curl"), 1));
        assert!(!c.should_intercept(Some("/usr/bin/wget"), 1));
        // Unknown command never matches command-based matchers.
        assert!(!c.should_intercept(None, 1));
    }

    #[test]
    fn blacklist_mode_starts_intercepting_everything() {
        let c = conf(vec![Action::Exclude(ProcessMatcher::suffix("ssh"))]);
        assert!(c.should_intercept(Some("/usr/bin/curl"), 1));
        assert!(!c.should_intercept(Some("/usr/bin/ssh"), 1));
    }

    #[test]
    fn exclude_removes_included_processes() {
        let c = conf(vec![
            Action::Include(ProcessMatcher::contains("browser")),
            Action::Exclude(ProcessMatcher::exact("/usr/bin/browser --safe")),
        ]);
        assert!(c.should_intercept(Some("/usr/bin/browser"), 1));
        assert!(!c.should_intercept(Some("/usr/bin/browser --safe"), 1));
    }

    #[test]
    fn pid_matcher_works_without_command() {
        let c = conf(vec![Action::Include(ProcessMatcher::PidRange {
            min: 100,
            max: 200,
        })]);
        assert!(c.should_intercept(None, 150));
        assert!(!c.should_intercept(None, 250));
        assert!(c.should_intercept(None, 100));
        assert!(c.should_intercept(None, 200));
    }

    #[test]
    fn all_matcher_catches_unknown_commands() {
        let c = conf(vec![Action::Include(ProcessMatcher::All)]);
        assert!(c.should_intercept(None, 1));
        assert!(c.should_intercept(Some("anything"), 1));
    }

    #[test]
    fn bind_interface_follows_decision() {
        let c = conf(vec![Action::Include(ProcessMatcher::prefix("/snap/"))]);
        assert_eq!(c.bind_interface(Some("/snap/firefox"), 9), Some(7));
        assert_eq!(c.bind_interface(Some("/usr/bin/firefox"), 9), None);
        assert_eq!(c.interface_id(), 7);
    }

    #[test]
    fn too_many_actions_is_rejected() {
        let actions: Vec<Action> = (0..MAX_ACTIONS + 1)
            .map(|_| Action::Include(ProcessMatcher::All))
            .collect();
        assert!(InterceptConf::new(actions, 1).is_err());
    }

    #[test]
    fn max_actions_is_accepted() {
        let actions: Vec<Action> = (0..MAX_ACTIONS)
            .map(|i| {
                if i % 2 == 0 {
                    Action::Include(ProcessMatcher::PidRange { min: i as u32, max: i as u32 })
                } else {
                    Action::Exclude(ProcessMatcher::PidRange { min: i as u32, max: i as u32 })
                }
            })
            .collect();
        let c = InterceptConf::new(actions, 1).expect("max actions accepted");
        // First action is an Include → whitelist mode; pid 0 matches first rule.
        assert!(c.should_intercept(None, 0));
        // pid 1 matches Include(0)? no; matches Exclude(1) → intercepted && !match → false.
        assert!(!c.should_intercept(None, 1));
    }

    #[test]
    fn order_matters_in_evaluation() {
        // Include-then-Exclude of the same process: excluded.
        let a = conf(vec![
            Action::Include(ProcessMatcher::All),
            Action::Exclude(ProcessMatcher::exact("x")),
        ]);
        assert!(!a.should_intercept(Some("x"), 1));
        // Exclude-first flips to blacklist mode, Include of same process re-adds it.
        let b = conf(vec![
            Action::Exclude(ProcessMatcher::exact("x")),
            Action::Include(ProcessMatcher::exact("x")),
        ]);
        assert!(b.should_intercept(Some("x"), 1));
        assert!(b.should_intercept(Some("other"), 1));
    }
}
