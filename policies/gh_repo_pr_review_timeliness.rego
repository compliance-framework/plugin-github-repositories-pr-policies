package compliance_framework.pr_review_timeliness

import future.keywords.if

two_weeks_ns := (((14 * 24) * 60) * 60) * 1e9

title := "Pull requests receive timely review attention"
description := "PRs should either be reviewed within two weeks or have active discussion. Unreviewed PRs or unresolved discussion threads older than two weeks indicate process risk."

risk_templates := [
	{
		"name": "Pull request has no reviews after two weeks",
		"title": "Unreviewed Pull Requests Indicate Breakdown of Code Review Process",
		"statement": "A pull request that has received no review activity after two weeks signals a breakdown in the code review process. Unreviewed code carries a higher risk of introducing defects, security vulnerabilities, or non-compliant changes. Extended review delays also increase branch divergence and make eventual review harder and less effective.",
		"likelihood_hint": "moderate",
		"impact_hint": "high",
		"violation_ids": ["pr_unreviewed_after_two_weeks"],
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
			"title": "Assign reviewers and establish a PR review SLA",
			"description": "Ensure all pull requests are assigned reviewers at creation and that a team-agreed SLA (e.g., first review within 2 business days) is enforced through automation or management oversight.",
			"tasks": [
				{"title": "Assign a reviewer to the stale pull request immediately"},
				{"title": "Define and communicate a team PR review SLA (e.g., first review within 2 business days)"},
				{"title": "Configure CODEOWNERS to auto-assign reviewers on PR creation"},
				{"title": "Enable stale PR notifications via GitHub Actions or a stale-bot integration"},
				{"title": "Consider requiring a reviewer assignment before a PR can be merged"},
			],
		},
	},
	{
		"name": "Unresolved review discussion thread older than two weeks",
		"title": "Unresolved Code Review Feedback Indicates Unaddressed Technical or Security Concerns",
		"statement": "Review threads that remain unresolved for more than two weeks indicate that raised concerns — which may include security findings, logic errors, or compliance issues — have not been addressed. Merging or leaving open code with unresolved review comments increases the risk that known problems persist in the codebase.",
		"likelihood_hint": "moderate",
		"impact_hint": "moderate",
		"violation_ids": ["stale_unresolved_review_thread"],
		"threat_refs": [
			{
				"system": "https://cwe.mitre.org",
				"external_id": "CWE-693",
				"title": "Protection Mechanism Failure",
				"url": "https://cwe.mitre.org/data/definitions/693.html",
			},
			{
				"system": "https://cwe.mitre.org",
				"external_id": "CWE-1059",
				"title": "Incomplete Documentation",
				"url": "https://cwe.mitre.org/data/definitions/1059.html",
			},
		],
		"remediation": {
			"title": "Resolve or explicitly dismiss all stale review threads",
			"description": "Address all unresolved review threads by fixing the raised issue, providing a documented reason for not addressing it, or explicitly resolving threads that are no longer applicable.",
			"tasks": [
				{"title": "Review all unresolved threads older than 14 days and action each one"},
				{"title": "Fix raised issues where the reviewer's concern is valid"},
				{"title": "Respond to threads where the concern does not apply, explaining why"},
				{"title": "Resolve threads that have been superseded by subsequent changes"},
				{"title": "Require all review threads to be resolved before a PR can be merged (via branch protection settings)"},
			],
		},
	},
]

violation[{"id": "pr_unreviewed_after_two_weeks", "remarks": pr_stale_remark(pr)}] if {
	pr := input_pull_requests[_]
	stale_pr_without_reviews(pr)
}

violation[{"id": "stale_unresolved_review_thread", "remarks": thread_stale_remark(pr)}] if {
	pr := input_pull_requests[_]
	some _ in stale_unresolved_threads(pr)
}

input_pull_requests := object.get(input, "pull_requests", [])

stale_pr_without_reviews(pr) if {
	not pr_has_reviews(pr)
	updated := pr_updated_at(pr)
	updated != ""
	pr_age_ns(updated) >= two_weeks_ns
}

stale_unresolved_threads(pr) := [thread |
	review := pr_reviews(pr)[_]
	thread := review_threads(review)[_]
	not thread_is_resolved(thread)
	thread_has_code_context(thread)
	last_comment_ns := latest_comment_ns(thread)
	last_comment_ns != -1
	pr_current_time_ns - last_comment_ns >= two_weeks_ns
]

pr_has_reviews(pr) if {
	count(pr_reviews(pr)) > 0
}

pr_reviews(pr) := object.get(pr, "reviews", [])

review_threads(review) := object.get(review, "threads", [])

thread_is_resolved(thread) := object.get(thread, "is_resolved", false)

thread_has_code_context(thread) if {
	comment := thread_comments(thread)[_]
	comment_path(comment) != ""
}

thread_comments(thread) := object.get(thread, "comments", [])

latest_comment_ns(thread) := max(times) if {
	times := {ts |
		comment := thread_comments(thread)[_]
		ts := comment_timestamp_ns(comment)
		ts >= 0
	}
	count(times) > 0
}

latest_comment_ns(thread) := -1 if {
	not thread_has_valid_comment_timestamp(thread)
}

thread_has_valid_comment_timestamp(thread) if {
	comment := thread_comments(thread)[_]
	comment_timestamp_ns(comment) >= 0
}

comment_timestamp_ns(comment) := time.parse_rfc3339_ns(ts) if {
	ts := comment_updated_at(comment)
	ts != ""
}

comment_timestamp_ns(comment) := time.parse_rfc3339_ns(ts) if {
	comment_updated_at(comment) == ""
	ts := comment_created_at(comment)
	ts != ""
}

comment_timestamp_ns(comment) := -1 if {
	comment_updated_at(comment) == ""
	comment_created_at(comment) == ""
}

comment_updated_at(comment) := object.get(comment, "updated_at", "")

comment_created_at(comment) := object.get(comment, "created_at", "")

comment_path(comment) := object.get(comment, "path", "")

pr_updated_at(pr) := object.get(pr, "updated_at", "")

pr_number(pr) := object.get(pr, "number", 0)

pr_title(pr) := object.get(pr, "title", "")

pr_title_or_placeholder(pr) := title if {
	title := trim_space(pr_title(pr))
	title != ""
}

pr_title_or_placeholder(pr) := "no title" if {
	trim_space(pr_title(pr)) == ""
}

pr_age_ns(timestamp) := pr_current_time_ns - time.parse_rfc3339_ns(timestamp)

pr_current_time_ns := object.get(input, "__now_ns", time.now_ns())

pr_stale_remark(pr) := sprintf("Pull request #%d (%s) was last updated %s and has no reviews after 14 days.", [
	pr_number(pr),
	pr_title_or_placeholder(pr),
	pr_updated_at(pr),
])

thread_stale_remark(pr) := sprintf("Pull request #%d (%s) has an unresolved discussion older than 14 days with no recent comments.", [
	pr_number(pr),
	pr_title_or_placeholder(pr),
])
