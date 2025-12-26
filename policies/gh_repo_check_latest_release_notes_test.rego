package compliance_framework.change_control_release_notes_exist

test_satisfies_exists if {
  inp := {"last_release": {"body": "Body with release notes"}}

  violations := { v | violation[v] with input as inp }
  count(violations) == 0
}

test_no_release_violation if {
  inp := {}
  violations := violation[v] with input as inp
  count(violation) == 1
  v.remarks == "No releases available for this repository."
}
test_no_release_notes_violation if {
  inp := { "last_release": {"body": ""} }
  violations := violation[v] with input as inp
  count(violation) == 1
  v.remarks == "Latest Release has no release notes."
}