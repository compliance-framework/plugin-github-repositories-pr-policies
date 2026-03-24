package compliance_framework.pr_age_three_weeks

import future.keywords.if

three_weeks_ns := 21 * 24 * 60 * 60 * 1e9

title := "Open pull requests are younger than three weeks"
description := "Pull requests should not remain open for more than three weeks without resolution."

risk_templates := [{
  "name": "Pull requests left open beyond three weeks",
  "title": "Stale Pull Requests Indicate Unresolved Code Review and Integration Risk",
  "statement": "Pull requests that remain open for more than three weeks without resolution signal delayed code review, unresolved conflicts, or accumulated drift from the target branch. Stale PRs increase integration complexity, may contain superseded or conflicting changes, and represent unreviewed code that can block security and compliance progress. Long-lived branches also increase the risk of merge conflicts introducing subtle bugs.",
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-710",
      "title": "Improper Adherence to Coding Standards",
      "url": "https://cwe.mitre.org/data/definitions/710.html"
    }
  ],
  "remediation": {
    "title": "Review and resolve or close stale pull requests",
    "description": "Triage all pull requests open beyond the three-week threshold: merge those that are ready, request updates on those awaiting author action, and close those that are no longer relevant.",
    "tasks": [
      { "title": "Review all PRs open beyond 21 days and assign a responsible reviewer or author action" },
      { "title": "Merge PRs that have received the required approvals and pass all checks" },
      { "title": "Close PRs that are no longer relevant or have been superseded" },
      { "title": "Establish a PR review SLA and communicate it to the team" },
      { "title": "Configure automated reminders or stale-bot to notify reviewers of aging PRs" }
    ]
  }
}]

violation[{"id": "stale_pull_request", "remarks": pr_age_remark(pr)}] if {
	pr := stale_pull_requests[_]
}

stale_pull_requests := [pr |
	pr := input_pull_requests[_]
	created_at := pr_updated_at(pr)
	created_at != ""
	age_ns := pr_age_ns(created_at)
	age_ns >= three_weeks_ns
]

input_pull_requests := object.get(input, "pull_requests", [])

current_time_ns := object.get(input, "__now_ns", time.now_ns())

pr_age_ns(created_at) := current_time_ns - time.parse_rfc3339_ns(created_at)

pr_age_days(pr) := floor(pr_age_ns(pr_updated_at(pr)) / nano_per_day)

nano_per_day := 24 * 60 * 60 * 1e9

pr_number(pr) := object.get(pr, "number", 0)

pr_title(pr) := object.get(pr, "title", "")

pr_updated_at(pr) := object.get(pr, "updated_at", "")

pr_age_remark(pr) := sprintf("Pull request #%d (%s) has been open for %d days (created %s) which exceeds the 3-week limit.", [
	pr_number(pr),
	pr_title_or_placeholder(pr),
	pr_age_days(pr),
	pr_updated_at(pr),
])

pr_title_or_placeholder(pr) := title if {
	title := trim_space(pr_title(pr))
	title != ""
}

pr_title_or_placeholder(pr) := "no title" if {
	trim_space(pr_title(pr)) == ""
}
