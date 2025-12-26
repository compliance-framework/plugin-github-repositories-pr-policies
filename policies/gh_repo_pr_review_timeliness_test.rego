package compliance_framework.pr_review_timeliness_test

import future.keywords.if
import data.compliance_framework.pr_review_timeliness as policy

current_time_ns := time.parse_rfc3339_ns("2025-01-15T00:00:00Z")

stale_pr_no_review_input := {
	"__now_ns": current_time_ns,
	"pull_requests": [
		{
			"number": 1,
			"title": "Add new feature",
			"updated_at": "2024-12-20T00:00:00Z",
			"reviews": [],
		},
	],
}

stale_thread_input := {
	"__now_ns": current_time_ns,
	"pull_requests": [
		{
			"number": 2,
			"title": "Refactor service",
			"updated_at": "2025-01-10T00:00:00Z",
			"reviews": [
				{
					"threads": [
						{
							"is_resolved": false,
							"comments": [
								{
									"path": "service.go",
									"created_at": "2024-12-20T00:00:00Z",
									"updated_at": "2024-12-20T00:00:00Z",
								},
							],
						},
					],
				},
			],
		},
	],
}

healthy_pr_input := {
	"__now_ns": current_time_ns,
	"pull_requests": [
		{
			"number": 3,
			"title": "Bugfix",
			"updated_at": "2025-01-12T00:00:00Z",
			"reviews": [
				{
					"threads": [
						{
							"is_resolved": true,
							"comments": [
								{
									"path": "bugfix.go",
									"created_at": "2025-01-11T00:00:00Z",
								},
							],
						},
					],
				},
			],
		},
	],
}

test_violation_for_pr_without_reviews if {
	violations := policy.violation with input as stale_pr_no_review_input
	count(violations) == 1
}

test_violation_for_stale_thread if {
	violations := policy.violation with input as stale_thread_input
	count(violations) == 1
}

test_recent_activity_passes if {
	violations := policy.violation with input as healthy_pr_input
	count(violations) == 0
}
