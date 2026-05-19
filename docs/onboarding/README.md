# Onboarding Guide

## Agent-assisted onboarding

### Week 1 outcomes
By the end of week 1, every new joiner should be able to:
- Set up the local and cloud development environment with agent assistance.
- Navigate the repository and explain the core project structure.
- Complete and submit a first small task with agent support.
- Apply safe agent usage practices (security, privacy, approval boundaries).
- Escalate to a human reviewer when confidence is low or approvals are required.

### Staged onboarding with mapped agent roles
1. **Stage 1: Environment setup**  
   **Agent role:** Environment/setup assistant  
   **Outcome:** Working local environment and repository access.
2. **Stage 2: Repository orientation**  
   **Agent role:** Repository navigation assistant  
   **Outcome:** New joiner can locate key files, workflows, and ownership boundaries.
3. **Stage 3: First ticket delivery**  
   **Agent role:** First-ticket implementation assistant  
   **Outcome:** Small scoped change prepared with clear rationale.
4. **Stage 4: Quality and review readiness**  
   **Agent role:** Review/quality assistant  
   **Outcome:** Change is validated, documented, and ready for human review.

### Standard prompts and guardrails
Use these stage prompts as a consistent baseline:

- **Setup prompt:** “Help me verify my environment is correctly configured for this repository and list any missing prerequisites.”
- **Navigation prompt:** “Map the files and folders relevant to `<feature-area>` and summarize what each one is responsible for.”
- **Implementation prompt:** “Help me complete `<ticket>` with the smallest safe change and highlight any assumptions before edits.”
- **Quality prompt:** “Review this change for correctness, security, and test impact; list what still needs human confirmation.”

Guardrails for all stages:
- Use only approved tools and repository-scoped context.
- Never expose secrets or sensitive content in prompts or outputs.
- Require human approval before high-impact changes or destructive actions.
- Ask for human help when requirements conflict, confidence is low, or business intent is unclear.
- Do not auto-apply broad or multi-area changes without explicit human confirmation.

### Day 1 agent playbook
Repeat these tasks for every new joiner:
1. **Task:** Validate setup and permissions.  
   **Expected output:** Checklist showing environment readiness and missing prerequisites.
2. **Task:** Generate a repository orientation summary.  
   **Expected output:** Short map of key paths, owner touchpoints, and workflow entry points.
3. **Task:** Propose a first-ticket plan.  
   **Expected output:** Scoped implementation plan, risks, and validation steps.
4. **Task:** Perform pre-review quality pass.  
   **Expected output:** Issue list (if any), validation status, and explicit human approval requests.

### Human handoff checkpoints
Human approval is required at these points:
- Access and environment confirmation.
- Architecture understanding check after orientation.
- First-ticket implementation plan approval before coding.
- First PR quality gate before merge readiness.

### Onboarding impact measurements
Track the following indicators:
- Time to first PR.
- Number of review iterations on first PR.
- Onboarding completion rate.
- Most common friction points by onboarding stage.

### Pilot and rollout
Run a pilot with one to two new joiners first:
1. Capture friction at each stage and checkpoint.
2. Update prompts, guardrails, and playbook tasks.
3. Re-run with the next cohort and compare onboarding metrics.
4. Roll out broadly once outcomes are stable and repeatable.
