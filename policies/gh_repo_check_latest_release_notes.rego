package compliance_framework.change_control_release_notes_exist

last_release := input.last_release

violation[{"remarks": "No releases available for this repository."}] if {
    not release_present
}

violation[{"remarks": "Latest Release has no release notes."}] if {
    release_present
    not release_has_notes
}

release_present if {
    last_release != null
}

release_has_notes if {
    # Require a non-empty Body field on the latest release
    body := last_release.body
    body != null
    trim_space(body) != ""
}

title := "Latest repository release has change notes"
description := "The latest repository release must include non-empty release notes."