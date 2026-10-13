package compliance_framework.pr_review_coverage_test

import data.compliance_framework.pr_review_coverage as policy
import future.keywords.if

loc_exempt_input := {"pull_requests": [{
	"number": 1,
	"title": "Tiny fix",
	"additions": 20,
	"deletions": 10,
	"changed_files": 5,
	"reviews": [],
}]}

adequate_review_input := {"pull_requests": [{
	"number": 2,
	"title": "Moderate update",
	"additions": 100,
	"deletions": 0,
	"changed_files": 3,
	"reviews": [{"threads": [
		{"comments": [{"path": "file1.go"}]},
		{"comments": [{"path": "file2.go"}]},
	]}],
}]}

insufficient_review_input := {"pull_requests": [{
	"number": 3,
	"title": "Large refactor",
	"additions": 120,
	"deletions": 40,
	"changed_files": 6,
	"reviews": [{"threads": [{"comments": [{"path": "only.go"}]}]}],
}]}

test_loc_threshold_passes if {
	violations := policy.violation with input as loc_exempt_input
	count(violations) == 0
}

test_sufficient_coverage_passes if {
	violations := policy.violation with input as adequate_review_input
	count(violations) == 0
}

test_insufficient_coverage_fails if {
	violations := policy.violation with input as insufficient_review_input
	count(violations) == 1
}
