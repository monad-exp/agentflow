Decide whether one repository-wide exploratory Hunt is justified at pinned commit `{commit_sha}`.

If a roam would add meaningful coverage beyond file and threat-model planning, call `bugdb.add_hunts` once with one `ROAM` Hunt, caller key `roam:v1`, and either no paths or a few optional starting points. Otherwise call `bugdb.add_hunts` once with an empty `hunts` array. Do not hunt yet.

All durable output belongs in BugDB. Your final response is only a short completion note and is not consumed downstream.
