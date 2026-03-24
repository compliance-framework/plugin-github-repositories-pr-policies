package compliance_framework.change_control_release_notes_exist

last_release := input.last_release

risk_templates := [
  {
    "name": "No release notes provided",
    "title": "Undocumented Releases Obscure Change History and Risk",
    "statement": "Releases without notes prevent stakeholders from understanding what changed, what was fixed, or what risks were introduced. This hinders security review, audit compliance, and incident response.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      }
    ],
    "remediation": {
      "title": "Require release notes for all published releases",
      "description": "Enforce a policy requiring meaningful release notes for every GitHub release, summarising changes, fixed issues, and any security-relevant modifications.",
      "tasks": [
        { "title": "Add release notes to all existing releases that are missing them" },
        { "title": "Use GitHub's auto-generated release notes feature or a CHANGELOG as a baseline" },
        { "title": "Automate release note generation from conventional commits or PR titles in CI/CD" },
        { "title": "Add a release checklist or PR template that includes release notes as a required step" }
      ]
    }
  }
]

violation[{"id": "no_release_present", "remarks": "No releases available for this repository."}] if {
    not release_present
}

violation[{"id": "release_has_no_notes", "remarks": "Latest Release has no release notes."}] if {
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