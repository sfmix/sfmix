use std::collections::HashSet;

/// Represents the identity of a looking glass user.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Identity {
    /// Whether the user is authenticated
    pub authenticated: bool,
    /// Email address (if authenticated)
    pub email: Option<String>,
    /// ASNs the user administers (extracted from group claims like "as64500")
    pub asns: HashSet<u32>,
    /// Raw group memberships from OIDC
    pub groups: HashSet<String>,
}

#[allow(dead_code)]
impl Identity {
    /// Anonymous/unauthenticated identity.
    pub fn anonymous() -> Self {
        Self {
            authenticated: false,
            email: None,
            asns: HashSet::new(),
            groups: HashSet::new(),
        }
    }

    /// Whether this identity has the admin group membership.
    pub fn is_admin(&self, admin_group: &str) -> bool {
        self.groups.contains(admin_group)
    }

    /// Whether this identity administers the given ASN.
    pub fn has_asn(&self, asn: u32) -> bool {
        self.asns.contains(&asn)
    }

    /// Build an authenticated identity from OIDC claims.
    pub fn from_oidc_claims(
        email: String,
        groups: Vec<String>,
        group_prefix: &str,
    ) -> Self {
        let mut asns = HashSet::new();
        for group in &groups {
            if let Some(asn_str) = group.strip_prefix(group_prefix) {
                if let Ok(asn) = asn_str.parse::<u32>() {
                    asns.insert(asn);
                }
            }
        }

        Self {
            authenticated: true,
            email: Some(email),
            asns,
            groups: groups.into_iter().collect(),
        }
    }
}
