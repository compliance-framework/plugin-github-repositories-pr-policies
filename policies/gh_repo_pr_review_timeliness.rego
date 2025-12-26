package compliance_framework.pr_review_timeliness

import future.keywords.if

two_weeks_ns := 14 * 24 * 60 * 60 * 1e9

title := "Pull requests receive timely review attention"
description := "PRs should either be reviewed within two weeks or have active discussion. Unreviewed PRs or unresolved discussion threads older than two weeks indicate process risk."

violation[{"remarks": pr_stale_remark(pr)}] if {
	pr := input_pull_requests[_]
	stale_pr_without_reviews(pr)
}

violation[{"remarks": thread_stale_remark(pr, thread)}] if {
	pr := input_pull_requests[_]
	thread := stale_unresolved_threads(pr)[_]
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

thread_stale_remark(pr, thread) := sprintf("Pull request #%d (%s) has an unresolved discussion older than 14 days with no recent comments.", [
	pr_number(pr),
	pr_title_or_placeholder(pr),
])
