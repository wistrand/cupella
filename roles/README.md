# Roles

Harness-neutral definitions of the agents Cupella starts for its stages. Each file's
header says what the role may read, write, and run; its body is the rule text the agent
gets. How a harness applies them is in [../agent_docs/harnesses.md](../agent_docs/harnesses.md):
Claude Code gets generated agent types (`.claude/agents/`, written by `./cupella setup`);
other harnesses get the body at the start of the subagent's prompt, with the header's
limits enforced by the harness where it can.

| Role        | Shell                                        | Used for |
|-------------|----------------------------------------------|----------|
| `reader`    | none                                         | analysis, reading areas, verification, benchmark analysis and scoring |
| `decryptor` | exactly the `./cupella` commands in its header   | the decryption stage |

Edit the roles here, never the generated files.
