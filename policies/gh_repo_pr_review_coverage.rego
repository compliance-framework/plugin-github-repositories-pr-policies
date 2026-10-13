package compliance_framework.pr_review_coverage

import future.keywords.if

coverage_threshold := 0.66
loc_threshold := 50

title := "Pull requests receive sufficient review coverage"
description := "Large pull requests must have reviewers cover at least 67% of changed files. Smaller PRs (under 50 LOC touched) are exempt."

risk_templates := [{
	"name": "Insufficient review file coverage on large pull requests",
	"title": "Code Changes Merged Without Adequate Reviewer Coverage",
	"statement": "Large pull requests where reviewers have not commented on a sufficient proportion of changed files are likely to contain unreviewed code. Unreviewed sections of a large changeset may harbour security vulnerabilities, logic errors, or compliance violations that would normally be caught by peer review, increasing the risk of defects reaching production.",
	"likelihood_hint": "moderate",
	"impact_hint": "high",
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title": "Protection Mechanism Failure",
			"url": "https://cwe.mitre.org/data/definitions/693.html",
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-284",
			"title": "Improper Access Control",
			"url": "https://cwe.mitre.org/data/definitions/284.html",
		},
	],
	"remediation": {
		"title": "Ensure reviewers cover sufficient files in large pull requests",
		"description": "Break large pull requests into smaller, focused changes that are easier to review thoroughly. Require that reviewers explicitly comment on or approve each changed file for significant changesets.",
		"tasks": [
			{"title": "Break up the pull request into smaller, logically independent changes if possible"},
			{"title": "Request additional reviewers to cover the full set of changed files"},
			{"title": "Ensure reviewers add inline comments or approvals covering at least 67% of changed files"},
			{"title": "Define a maximum PR size policy (e.g., 400 LOC) and enforce it through team guidelines"},
			{"title": "Consider tooling (e.g., danger.js, reviewdog) to automatically flag under-reviewed PRs"},
		],
	},
}]

violation[{"id": "insufficient_review_coverage", "remarks": pr_coverage_remark(pr)}] if {
	pr := input_pull_requests[_]
	not pr_meets_loc_exception(pr)
	not pr_has_sufficient_review(pr)
}

input_pull_requests := object.get(input, "pull_requests", [])

pr_meets_loc_exception(pr) if {
	pr_total_loc(pr) < loc_threshold
}

pr_has_sufficient_review(pr) if {
	required := required_reviewed_files(pr)
	reviewed := pr_reviewed_files(pr)
	reviewed >= required
}

required_reviewed_files(pr) := 0 if {
	pr_changed_files(pr) <= 0
}

required_reviewed_files(pr) := required if {
	pr_changed_files(pr) > 0
	required := ceil(coverage_threshold * pr_changed_files(pr))
}

pr_reviewed_files(pr) := count(reviewed_paths(pr))

reviewed_paths(pr) := {path |
	review := pr_reviews(pr)[_]
	thread := review_threads(review)[_]
	comment := thread_comments(thread)[_]
	path := comment_path(comment)
	path != ""
}

pr_total_loc(pr) := pr_additions(pr) + pr_deletions(pr)

pr_additions(pr) := object.get(pr, "additions", 0)

pr_deletions(pr) := object.get(pr, "deletions", 0)

pr_changed_files(pr) := object.get(pr, "changed_files", 0)

pr_reviews(pr) := object.get(pr, "reviews", [])

review_threads(review) := object.get(review, "threads", [])

thread_comments(thread) := object.get(thread, "comments", [])

comment_path(comment) := object.get(comment, "path", "")

pr_number(pr) := object.get(pr, "number", 0)

pr_title(pr) := object.get(pr, "title", "")

pr_title_or_placeholder(pr) := title if {
	title := trim_space(pr_title(pr))
	title != ""
} else := "no title"

pr_coverage_remark(pr) := sprintf("Pull request #%d (%s) has %d LOC touched and only %d/%d reviewed files (required 67%% coverage).", [
	pr_number(pr),
	pr_title_or_placeholder(pr),
	pr_total_loc(pr),
	pr_reviewed_files(pr),
	pr_changed_files(pr),
])
