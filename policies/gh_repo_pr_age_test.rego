package compliance_framework.pr_age_three_weeks_test

import future.keywords.if
import data.compliance_framework.pr_age_three_weeks as policy

test_no_violation_when_all_recent if {
	inp := {
		"pull_requests": [
			{
				"number": 1,
				"title": "Refactor auth",
				"updated_at": "2025-01-01T00:00:00Z",
			},
		],
		"__now_ns": time.parse_rfc3339_ns("2025-01-15T00:00:00Z"),
	}
	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_pr_older_than_three_weeks if {
	inp := {
		"pull_requests": [
			{
				"number": 42,
				"title": "Add multi-region support",
				"updated_at": "2024-12-01T00:00:00Z",
			},
		],
		"__now_ns": time.parse_rfc3339_ns("2025-01-10T00:00:00Z"),
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}
