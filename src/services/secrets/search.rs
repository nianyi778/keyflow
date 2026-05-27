//! Search and ranking logic for secrets.
//!
//! Extracted to keep the main SecretService module focused.

use serde::Serialize;

use crate::models::{KeyStatus, SecretEntry};
use crate::services::secrets::CanonicalName;

#[derive(Debug, Clone, Serialize)]
pub struct RankedSecretEntry {
    pub entry: SecretEntry,
    pub relevance_score: i64,
    pub matched_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SearchFilter {
    pub provider: Option<String>,
    pub project: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub include_inactive: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub found: bool,
    pub total: usize,
    pub count: usize,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
    pub keys: Vec<RankedSecretEntry>,
}

pub(crate) fn clamp_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(20).clamp(1, 100)
}

pub(crate) fn normalized_offset(offset: Option<usize>) -> usize {
    offset.unwrap_or(0)
}

pub(crate) fn paginate_items<T>(
    items: Vec<T>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Vec<T> {
    let offset = normalized_offset(offset);
    let limit = clamp_limit(limit);
    items.into_iter().skip(offset).take(limit).collect()
}

pub fn search_ranked_impl(
    entries: Vec<SecretEntry>,
    query: &str,
    filter: &SearchFilter,
) -> SearchResult {
    let canonical_query = CanonicalName::from(query);

    let mut filtered = entries
        .into_iter()
        .filter(|entry| filter.include_inactive || entry.is_active)
        .filter(|entry| {
            filter
                .provider
                .as_ref()
                .is_none_or(|provider| entry.provider == *provider)
        })
        .filter(|entry| {
            filter
                .project
                .as_ref()
                .is_none_or(|project| entry.projects.iter().any(|item| item == project))
        })
        .collect::<Vec<_>>();

    let scored = rank_entries_for_query(filtered.as_mut_slice(), &canonical_query);
    let total = filtered.len();
    let limit = clamp_limit(filter.limit);
    let offset = normalized_offset(filter.offset);
    let keys = paginate_items(scored, filter.limit, filter.offset);

    SearchResult {
        found: !keys.is_empty(),
        total,
        count: keys.len(),
        limit,
        offset,
        has_more: offset + keys.len() < total,
        keys,
    }
}

pub(crate) fn rank_entries_for_query(
    entries: &mut [SecretEntry],
    query: &CanonicalName,
) -> Vec<RankedSecretEntry> {
    let query_str = query.as_str().trim();
    let mut scored = entries
        .iter()
        .cloned()
        .map(|entry| {
            let (score, matched_fields) = score_entry(&entry, query_str);
            RankedSecretEntry {
                entry,
                relevance_score: score,
                matched_fields: matched_fields.into_iter().map(str::to_string).collect(),
            }
        })
        .collect::<Vec<_>>();
    scored.sort_by(|a, b| {
        b.relevance_score
            .cmp(&a.relevance_score)
            .then_with(|| b.entry.is_active.cmp(&a.entry.is_active))
            .then_with(|| {
                a.entry
                    .metadata_gaps()
                    .len()
                    .cmp(&b.entry.metadata_gaps().len())
            })
            .then_with(|| a.entry.name.cmp(&b.entry.name))
    });
    scored
}

fn score_entry(entry: &SecretEntry, query: &str) -> (i64, Vec<&'static str>) {
    let query_lower = query.to_ascii_lowercase();
    let query_upper = query.to_ascii_uppercase();
    let mut score = 0;
    let mut fields = Vec::new();

    let name_lower = entry.name.to_ascii_lowercase();
    let env_upper = entry.env_var.to_ascii_uppercase();
    let provider_lower = entry.provider.to_ascii_lowercase();
    let account_lower = entry.account_name.to_ascii_lowercase();
    let org_lower = entry.org_name.to_ascii_lowercase();
    let description_lower = entry.description.to_ascii_lowercase();

    if entry.name == query || name_lower == query_lower {
        score += 120;
        fields.push("name");
    } else if name_lower.contains(&query_lower) {
        score += 70;
        fields.push("name");
    }

    if entry.env_var == query || env_upper == query_upper {
        score += 140;
        fields.push("env_var");
    } else if env_upper.contains(&query_upper) {
        score += 90;
        fields.push("env_var");
    }

    if entry.provider == query || provider_lower == query_lower {
        score += 80;
        fields.push("provider");
    } else if provider_lower.contains(&query_lower) {
        score += 45;
        fields.push("provider");
    }

    if account_lower.contains(&query_lower) {
        score += 30;
        fields.push("account_name");
    }
    if org_lower.contains(&query_lower) {
        score += 25;
        fields.push("org_name");
    }
    if description_lower.contains(&query_lower) {
        score += 20;
        fields.push("description");
    }
    if entry.projects.iter().any(|project| {
        project.eq_ignore_ascii_case(query) || project.to_ascii_lowercase().contains(&query_lower)
    }) {
        score += 55;
        fields.push("projects");
    }
    if entry
        .scopes
        .iter()
        .any(|scope| scope.to_ascii_lowercase().contains(&query_lower))
    {
        score += 15;
        fields.push("scopes");
    }

    if entry.is_active {
        score += 5;
    }
    if matches!(entry.status(), KeyStatus::Expired) {
        score -= 15;
    }

    fields.sort_unstable();
    fields.dedup();
    (score, fields)
}
