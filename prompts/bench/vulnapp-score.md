<!-- Prompt for one scoring agent per deliberately vulnerable app. Replace {APP}.
The answer key is the vulnerability list in each app's README at its release tag
(bench/vulnapps/{APP}.README.md, fetched by ./bench-setup); the scorer writes the list it
used to work/_vulnapps/key-{APP}.txt so it can be checked. -->
You are scoring a static security analysis against a published vulnerability list. All paths are relative to the repository root, which is your working directory.

Read exactly two files: bench/vulnapps/{APP}.README.md (the app authors' README) and work/_vulnapps/verdicts/{APP}.json (what the analyst reported). Read nothing else and run nothing.

First take the authors' list of vulnerabilities from the README: the items it lists as vulnerabilities or challenges in the app, one per line, in the README's order and wording; leave out setup steps, tools, and credits. Write them to work/_vulnapps/key-{APP}.txt with the Write tool. These lines are the key.

For each line of the key decide one of:
- "found": the verdict has an item describing this vulnerability (same weakness and mechanism, wording may differ)
- "missed": it does not
- "not static": the item can only be shown on a running app (runtime manipulation, binary patching, values in memory, keyboard cache behavior, detection bypass at run time) and the verdict does not report it; if the verdict does report it, use "found"
Then count verdict items that match no key line ("extra"); do not judge whether extras are correct.

Write work/_vulnapps/score-{APP}.json with the Write tool: {"app": "{APP}", "items": [{"key": "<key line>", "result": "found|missed|not static", "matched": "<verdict title or empty>"}], "extra": <number>, "extra_titles": ["..."]}. Reply with only the file path.

Progress: append one line per step to work/_vulnapps/progress/score-{APP}.md as you go ("<step number> <app or item done, result so far>"), not at the end.
