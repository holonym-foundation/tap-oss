//! Permissiveness analysis for policy changes.
//!
//! Single source of truth for "does this policy change REDUCE human gating?".
//! Used by the proposal review surface (so a manager sees, at a glance, every
//! way a proposed change loosens enforcement) and reusable by the proxy's AI
//! safety summary. Kept in `tap-core` so there is no duplicated logic in the
//! dashboard JS.

use crate::config::PolicyConfig;
use serde::Serialize;

/// The policy fields relevant to permissiveness, normalized for comparison.
/// Built from either a stored `PolicyConfig` or a proposed change.
#[derive(Debug, Clone)]
pub struct PolicyView {
    pub auto_approve_methods: Vec<String>,
    pub require_approval_methods: Vec<String>,
    pub auto_approve_urls: Vec<String>,
    pub require_approval_urls: Vec<String>,
    pub require_passkey: bool,
    pub min_approvals: u32,
    pub allowed_approvers: Vec<String>,
}

impl PolicyView {
    /// The implicit default when a credential has no explicit policy: GET/HEAD
    /// auto-approved, everything else requires approval, no passkey, single
    /// approver, no approver restriction (see `policy::evaluate_policy`). Used
    /// as the baseline when a proposal CREATES a policy where none existed, so
    /// "auto-approve POST" is correctly flagged as more permissive than default.
    pub fn default_baseline() -> Self {
        Self {
            auto_approve_methods: vec!["GET".into(), "HEAD".into()],
            require_approval_methods: vec![],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            require_passkey: false,
            min_approvals: 1,
            allowed_approvers: vec![],
        }
    }

    pub fn from_config(p: &PolicyConfig) -> Self {
        let (require_passkey, min_approvals, allowed_approvers) = match &p.approval {
            Some(a) => (
                a.require_passkey,
                a.min_approvals,
                a.allowed_approvers.clone(),
            ),
            None => (false, 1, vec![]),
        };
        Self {
            auto_approve_methods: normalize_methods(&p.auto_approve),
            require_approval_methods: normalize_methods(&p.require_approval),
            auto_approve_urls: p.auto_approve_urls.clone(),
            require_approval_urls: p.require_approval_urls.clone(),
            require_passkey,
            min_approvals,
            allowed_approvers,
        }
    }
}

fn normalize_methods(methods: &[String]) -> Vec<String> {
    methods.iter().map(|m| m.to_uppercase()).collect()
}

/// One way a proposed change reduces human gating. `field` is machine-readable
/// (for grouping/styling); `summary` is human-facing (the chip text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermissiveChange {
    pub field: String,
    pub summary: String,
}

/// Compute every way `new` is MORE permissive than `old` (or, when `old` is
/// `None`, more permissive than the no-policy default). An empty result means
/// the change is neutral or strictly more restrictive.
pub fn permissive_changes(old: Option<&PolicyView>, new: &PolicyView) -> Vec<PermissiveChange> {
    let baseline = PolicyView::default_baseline();
    let old = old.unwrap_or(&baseline);
    let mut changes = Vec::new();

    // 1. Methods newly auto-approved. (Removing a method from require_approval
    //    is NOT permissive on its own: unlisted methods still default to
    //    require-approval — only being added to auto_approve flips it to auto.)
    for m in &new.auto_approve_methods {
        if !old.auto_approve_methods.contains(m) {
            changes.push(PermissiveChange {
                field: "auto_approve_methods".into(),
                summary: format!("{m} requests will be auto-approved (no human approval)"),
            });
        }
    }

    // 2. URL patterns newly auto-approved (bypass approval regardless of method).
    for u in &new.auto_approve_urls {
        if !old.auto_approve_urls.contains(u) {
            changes.push(PermissiveChange {
                field: "auto_approve_urls".into(),
                summary: format!("requests matching \"{u}\" will be auto-approved"),
            });
        }
    }

    // 3. URL safety overrides removed. Adding require_approval_urls is
    //    restrictive, but removing them can expose requests previously forced
    //    through human review to broader auto-approve rules.
    for u in &old.require_approval_urls {
        if !new.require_approval_urls.contains(u) {
            changes.push(PermissiveChange {
                field: "require_approval_urls".into(),
                summary: format!(
                    "requests matching \"{u}\" will no longer be forced to require approval"
                ),
            });
        }
    }

    // 4. Passkey requirement dropped (weaker approval strength).
    if old.require_passkey && !new.require_passkey {
        changes.push(PermissiveChange {
            field: "require_passkey".into(),
            summary: "passkey will no longer be required to approve".into(),
        });
    }

    // 5. Fewer approvers required.
    if new.min_approvals < old.min_approvals {
        changes.push(PermissiveChange {
            field: "min_approvals".into(),
            summary: format!(
                "approvals required drops from {} to {}",
                old.min_approvals, new.min_approvals
            ),
        });
    }

    // 6. Approver set widened (broader trust surface). An empty list means
    //    "anyone in the channel", so non-empty -> empty is a widening, and any
    //    newly-added approver email is a widening.
    if !old.allowed_approvers.is_empty() && new.allowed_approvers.is_empty() {
        changes.push(PermissiveChange {
            field: "allowed_approvers".into(),
            summary: "approval no longer restricted to specific approvers".into(),
        });
    } else {
        for a in &new.allowed_approvers {
            if !old.allowed_approvers.contains(a) {
                changes.push(PermissiveChange {
                    field: "allowed_approvers".into(),
                    summary: format!("{a} added as an allowed approver"),
                });
            }
        }
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PolicyView {
        PolicyView {
            auto_approve_methods: vec!["GET".into()],
            require_approval_methods: vec!["POST".into()],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            require_passkey: true,
            min_approvals: 2,
            allowed_approvers: vec!["a@x.com".into()],
        }
    }

    #[test]
    fn no_change_is_empty() {
        let p = base();
        assert!(permissive_changes(Some(&p), &p).is_empty());
    }

    #[test]
    fn auto_approve_method_added_is_flagged() {
        let old = base();
        let mut new = base();
        new.auto_approve_methods.push("POST".into());
        let c = permissive_changes(Some(&old), &new);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "auto_approve_methods");
    }

    #[test]
    fn auto_approve_url_added_is_flagged() {
        let old = base();
        let mut new = base();
        new.auto_approve_urls.push("/v1/send".into());
        let c = permissive_changes(Some(&old), &new);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "auto_approve_urls");
    }

    #[test]
    fn require_approval_url_removed_is_flagged() {
        let mut old = base();
        old.require_approval_urls = vec!["/git/refs/heads".into()];
        let new = base();
        let c = permissive_changes(Some(&old), &new);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "require_approval_urls");
    }

    #[test]
    fn passkey_disabled_is_flagged() {
        let old = base();
        let mut new = base();
        new.require_passkey = false;
        let c = permissive_changes(Some(&old), &new);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "require_passkey");
    }

    #[test]
    fn min_approvals_lowered_is_flagged() {
        let old = base();
        let mut new = base();
        new.min_approvals = 1;
        let c = permissive_changes(Some(&old), &new);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "min_approvals");
    }

    #[test]
    fn approvers_widened_is_flagged() {
        let old = base();
        let mut new = base();
        new.allowed_approvers.push("b@x.com".into());
        let c = permissive_changes(Some(&old), &new);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "allowed_approvers");
    }

    #[test]
    fn clearing_approver_restriction_is_flagged() {
        let old = base();
        let mut new = base();
        new.allowed_approvers = vec![];
        let c = permissive_changes(Some(&old), &new);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "allowed_approvers");
    }

    #[test]
    fn require_approval_removal_alone_is_not_flagged() {
        // Removing POST from require_approval (without adding it to auto_approve)
        // keeps it require-by-default -> NOT permissive.
        let old = base();
        let mut new = base();
        new.require_approval_methods = vec![];
        assert!(permissive_changes(Some(&old), &new).is_empty());
    }

    #[test]
    fn restrictive_changes_not_flagged() {
        let old = base();
        let mut new = base();
        new.require_passkey = true; // unchanged
        new.min_approvals = 3; // more approvers = stricter
        new.auto_approve_methods = vec![]; // fewer auto = stricter
        assert!(permissive_changes(Some(&old), &new).is_empty());
    }

    #[test]
    fn creating_policy_that_auto_approves_post_is_flagged_vs_default() {
        // old = None -> baseline (GET/HEAD auto). Auto-approving POST is more
        // permissive than the no-policy default.
        let new = PolicyView {
            auto_approve_methods: vec!["GET".into(), "HEAD".into(), "POST".into()],
            require_approval_methods: vec![],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            require_passkey: false,
            min_approvals: 1,
            allowed_approvers: vec![],
        };
        let c = permissive_changes(None, &new);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "auto_approve_methods");
        assert!(c[0].summary.contains("POST"));
    }
}
