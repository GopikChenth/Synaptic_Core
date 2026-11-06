//! Semantic 3-Way Merge Algorithm (diff3).
//!
//! Performs line-level 3-way reconciliation across Base, Local, and Remote versions.
//! Distinguishes clean non-overlapping edits from conflicting regions.

use serde::{Deserialize, Serialize};
use similar::{DiffTag, TextDiff};

/// Type of diff hunk in 3-way comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HunkType {
    Unchanged,
    LocalChange,
    RemoteChange,
    IdenticalChange,
    Conflict,
}

/// Represents an individual region in the 3-way diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffHunk {
    pub hunk_type: HunkType,
    pub base_lines: Vec<String>,
    pub local_lines: Vec<String>,
    pub remote_lines: Vec<String>,
}

/// Result of 3-way semantic merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeResult {
    /// Merged cleanly with no overlapping modifications.
    Clean(String),
    /// Overlapping modifications detected, requiring quarantine and user inspection.
    Conflict {
        overlapping_lines_count: usize,
        hunks: Vec<DiffHunk>,
    },
}

/// Executes line-level 3-way merge across base, local, and remote contents.
pub fn merge3(base_str: &str, local_str: &str, remote_str: &str) -> MergeResult {
    let base_lines: Vec<&str> = base_str.lines().collect();
    let local_lines: Vec<&str> = local_str.lines().collect();
    let remote_lines: Vec<&str> = remote_str.lines().collect();

    // Fast-path identical cases
    if local_str == remote_str {
        return MergeResult::Clean(local_str.to_string());
    }
    if base_str == local_str {
        return MergeResult::Clean(remote_str.to_string());
    }
    if base_str == remote_str {
        return MergeResult::Clean(local_str.to_string());
    }

    // Capture diff operations against base
    let diff_local = TextDiff::from_lines(base_str, local_str);
    let diff_remote = TextDiff::from_lines(base_str, remote_str);

    // Identify edit intervals in base for local
    let mut local_edits = Vec::new();
    for op in diff_local.ops() {
        let (tag, old_range, new_range) = (op.tag(), op.old_range(), op.new_range());
        if tag != DiffTag::Equal {
            let replaced: Vec<String> = local_lines[new_range].iter().map(|s| s.to_string()).collect();
            local_edits.push((old_range.start, old_range.end, replaced));
        }
    }

    // Identify edit intervals in base for remote
    let mut remote_edits = Vec::new();
    for op in diff_remote.ops() {
        let (tag, old_range, new_range) = (op.tag(), op.old_range(), op.new_range());
        if tag != DiffTag::Equal {
            let replaced: Vec<String> = remote_lines[new_range].iter().map(|s| s.to_string()).collect();
            remote_edits.push((old_range.start, old_range.end, replaced));
        }
    }

    // Collect all critical boundary line numbers on the base sequence
    let mut cut_points = std::collections::BTreeSet::new();
    cut_points.insert(0);
    cut_points.insert(base_lines.len());

    for (start, end, _) in &local_edits {
        cut_points.insert(*start);
        cut_points.insert(*end);
    }
    for (start, end, _) in &remote_edits {
        cut_points.insert(*start);
        cut_points.insert(*end);
    }

    let cuts: Vec<usize> = cut_points.into_iter().collect();
    let mut hunks = Vec::new();
    let mut merged_output = Vec::new();
    let mut has_conflict = false;
    let mut total_overlapping_lines = 0;

    for i in 0..cuts.len() - 1 {
        let b_start = cuts[i];
        let b_end = cuts[i + 1];

        let base_slice: Vec<String> = if b_start < base_lines.len() {
            base_lines[b_start..b_end.min(base_lines.len())]
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            Vec::new()
        };

        // Find if local modified this exact slice or overlapping range
        let local_mod = local_edits.iter().find(|(s, e, _)| *s <= b_start && *e >= b_end);
        let remote_mod = remote_edits.iter().find(|(s, e, _)| *s <= b_start && *e >= b_end);

        match (local_mod, remote_mod) {
            (None, None) => {
                // Neither modified this slice: keep base
                hunks.push(DiffHunk {
                    hunk_type: HunkType::Unchanged,
                    base_lines: base_slice.clone(),
                    local_lines: base_slice.clone(),
                    remote_lines: base_slice.clone(),
                });
                merged_output.extend(base_slice);
            }
            (Some((ls, le, l_rep)), None) => {
                // Local only modified
                let l_slice = if *ls == b_start && *le == b_end {
                    l_rep.clone()
                } else {
                    // Partial slice representation
                    l_rep.clone()
                };
                hunks.push(DiffHunk {
                    hunk_type: HunkType::LocalChange,
                    base_lines: base_slice.clone(),
                    local_lines: l_slice.clone(),
                    remote_lines: base_slice,
                });
                merged_output.extend(l_slice);
            }
            (None, Some((rs, re, r_rep))) => {
                // Remote only modified
                let r_slice = if *rs == b_start && *re == b_end {
                    r_rep.clone()
                } else {
                    r_rep.clone()
                };
                hunks.push(DiffHunk {
                    hunk_type: HunkType::RemoteChange,
                    base_lines: base_slice.clone(),
                    local_lines: base_slice,
                    remote_lines: r_slice.clone(),
                });
                merged_output.extend(r_slice);
            }
            (Some((_, _, l_rep)), Some((_, _, r_rep))) => {
                // Both modified
                if l_rep == r_rep {
                    // Identical change
                    hunks.push(DiffHunk {
                        hunk_type: HunkType::IdenticalChange,
                        base_lines: base_slice,
                        local_lines: l_rep.clone(),
                        remote_lines: r_rep.clone(),
                    });
                    merged_output.extend(l_rep.clone());
                } else {
                    // Overlapping conflicting change!
                    has_conflict = true;
                    let overlap = l_rep.len().max(r_rep.len()).max(1);
                    total_overlapping_lines += overlap;

                    hunks.push(DiffHunk {
                        hunk_type: HunkType::Conflict,
                        base_lines: base_slice,
                        local_lines: l_rep.clone(),
                        remote_lines: r_rep.clone(),
                    });
                }
            }
        }
    }

    if has_conflict {
        MergeResult::Conflict {
            overlapping_lines_count: total_overlapping_lines,
            hunks,
        }
    } else {
        let mut final_text = merged_output.join("\n");
        if (local_str.ends_with('\n') || remote_str.ends_with('\n')) && !final_text.is_empty() {
            final_text.push('\n');
        }
        MergeResult::Clean(final_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_non_overlapping_merge() {
        let base = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5\n";
        // Local edits Line 1
        let local = "Line 1 modified by local\nLine 2\nLine 3\nLine 4\nLine 5\n";
        // Remote edits Line 5
        let remote = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5 modified by remote\n";

        match merge3(base, local, remote) {
            MergeResult::Clean(merged) => {
                assert!(merged.contains("Line 1 modified by local"));
                assert!(merged.contains("Line 5 modified by remote"));
                assert!(merged.contains("Line 3"));
            }
            MergeResult::Conflict { .. } => panic!("Expected clean merge for non-overlapping edits"),
        }
    }

    #[test]
    fn test_overlapping_conflict() {
        let base = "Header\nShared Content\nFooter\n";
        let local = "Header\nShared Content edited by Alice\nFooter\n";
        let remote = "Header\nShared Content edited by Bob\nFooter\n";

        match merge3(base, local, remote) {
            MergeResult::Conflict { overlapping_lines_count, hunks } => {
                assert!(overlapping_lines_count > 0);
                let conflict_hunk = hunks.iter().find(|h| h.hunk_type == HunkType::Conflict);
                assert!(conflict_hunk.is_some());
            }
            MergeResult::Clean(_) => panic!("Expected conflict for overlapping edit"),
        }
    }
}
