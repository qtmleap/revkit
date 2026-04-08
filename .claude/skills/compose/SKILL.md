---
name: compose
description: Assemble an Agent Team as leader and run the plan → approve → execute workflow
user_invocable: true
---

# /compose — Agent Teams Workflow

You are the **leader agent** for this project. Follow this workflow strictly.

## Phase 1: Hearing

Ask the user **what they want to achieve**. Keep it brief — 1-2 sentences.
If the user already specified a task in their message, use that directly.

## Phase 2: Planning

Once you have the user's goal:

1. Check available agents (under `.claude/agents/`):
   - **tweak-engineer**: iOS Tweak development (Orion/Theos, ElleKit C hooks)
   - **frida-engineer**: Frida hook scripts, runtime analysis
   - **mitmproxy-engineer**: mitmproxy addons, traffic capture
   - **python-engineer**: MSL client, decoders, data processing
   - **log-monitor**: Frida/mitmproxy/Tweak log monitoring, MSL decryption status reports

2. Have each relevant agent propose subtasks in **Plan mode**:
   - Launch agents via the Agent tool: "Propose the subtasks you should own for this goal as a bullet list (do not write code)"
   - Launch in parallel for efficiency

3. Consolidate proposals and save a plan document to `docs/plans/`:

```markdown
# Work Plan: [Title]
Date: [ISO 8601]

## Goal
[User's goal]

## Tasks

### [Agent Name]
- [ ] Subtask 1
- [ ] Subtask 2

### [Agent Name]
- [ ] Subtask 1

## Execution Order
1. Parallel: [task group]
2. Sequential: [task group]

## Deliverables
- [file path]: [description]

## Risks / Notes
- [known issues]
```

## Phase 3: Approval

Present the plan to the user and confirm:
- "Shall I proceed with this plan?"
- Incorporate any requested changes

**Do NOT proceed to Phase 4 without explicit user approval.**

## Phase 4: Execution

After approval:

1. Create a task list with TodoWrite
2. Launch agents via the Agent tool (in parallel where possible)
   - Provide each agent with specific file paths, changes, and constraints
3. Tweak builds run in the theos sidecar container:
   ```bash
   docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/<tweak> clean
   docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/<tweak> package install THEOS_DEVICE_IP=192.168.0.49
   ```
4. Check iOS device logs via iproxy (`ssh -p 2222 root@host.docker.internal`)
   If unreachable, ask the user to run `iproxy 2222 22` on the host Mac
5. Review each agent's results

## Phase 5: Report

After all tasks are complete:
1. Update checkboxes in the plan document
2. Update related spec documents
3. Report results and remaining issues to the user

## Constraints

- Do not guess or speculate — say "unknown" when unsure
- Verify the full blast radius before making changes
- Code style: Python uses `uv run ruff format`, commit messages follow commitlint
- Documentation goes in `docs/`
- **Language**: All inter-agent communication (prompts and responses) MUST be in English. Only when the leader replies to the user, match the user's language
