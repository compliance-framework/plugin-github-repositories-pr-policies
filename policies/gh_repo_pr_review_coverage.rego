package compliance_framework.pr_review_coverage

import future.keywords.if

coverage_threshold := 0.66
loc_threshold := 50

title := "Pull requests receive sufficient review coverage"
description := "Large pull requests must have reviewers cover at least 67% of changed files. Smaller PRs (under 50 LOC touched) are exempt."

violation[{"remarks": pr_coverage_remark(pr)}] if {
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
