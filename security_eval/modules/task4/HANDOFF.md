# Task 4 handoff

This package owns the AgentDojo application-security evaluation for task 4. It only communicates with the rest of the application through the contract models in `security_eval.contracts`.

## Install and register

Use Python 3.11 and install the shared requirements plus `requirements/task4.in`. The module manifest is `security_eval/modules/task4/module.json`; add that path to `MODULE_MANIFEST_PATHS` or let `ModuleRegistry.discover()` scan `security_eval/modules`.

Real runs require an OpenAI-compatible endpoint with native chat tool-calling support. `TARGET_BASE_URL` and `TARGET_API_KEY` are taken from the shared target client, while `AGENTDOJO_MODEL` selects the API model. The common aliases `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, and `gpt-3.5-turbo` are mapped to AgentDojo's known snapshots, and exact supported snapshot names are preserved. Any other non-empty model ID is passed unchanged to the target API while AgentDojo uses its generic `local` identity only for attack-template wording. For those generic targets, AgentDojo's OpenAI-only `developer` role is normalized to the widely supported `system` role at the private client boundary. This permits Qwen, DeepSeek, provider-prefixed, and competition-specific model IDs without changing the public configuration or result format. The target must still implement native OpenAI-compatible chat tool calls.

## Benchmark and modes

- Project benchmark version: `v1`
- AgentDojo package: `0.1.35`
- AgentDojo suite: `workspace` version `v1.2.2`
- Module version: `1.1.0`; only `defense=none` cases are executed in all modes.
- `benchmark`: 8 quick or 24 full sandbox runs, selected in frozen-matrix order.
- `dynamic`: seeded, previously uncovered user/injection/attack combinations, up to 6 quick or 18 full runs. The same original combination budget is retained without defense duplicates.
- `hybrid`: frozen matrix followed by dynamic cases only for categories below 80 or containing invalid cases.

Hybrid therefore runs at most 14 quick or 42 full cases. Estimates and frontend case totals refer to executed cases, not the stored bank. The frozen v1 matrix and manifest remain byte-for-byte unchanged (16 quick / 48 full stored entries); the loader still verifies their identities, counts and SHA-256 before selecting the unfiltered subset. Version `1.1.0` distinguishes the new execution policy from historical paired results. Do not compare the two policies' aggregate scores as if their denominators were identical.

ToolFilter is no longer constructed or executed through `Task4Module`. Its private adapter compatibility path, pairing helper, and the module-1.0.0 contract fixture are retained for historical compatibility and rollback, not as active competition tests. Public settings, request fields, contract version, scoring formula and artifact paths are unchanged. Historical run files are not rewritten.

Every case creates a fresh workspace environment. DoS cases only test instruction-induced abandonment of the authorized task; they never perform resource exhaustion or network attacks.

## Results and artifacts

`Task4Module.run()` returns only a validated `TaskResult`. Case-level scores include utility, utility-under-attack, targeted ASR, unauthorized tool-call rate, leakage rate, DoS interruption rate and security score. Defense utility loss and paired case IDs are not applicable to current unfiltered runs and are omitted rather than reported as zero. Invalid cases are excluded from metric denominators. Benchmark/dynamic 60/40 fusion and single-source behavior are unchanged.

Sanitized traces are stored below the run directory as `task_4/cases/<case_id>.json`. They contain tool names and diff paths, not full system prompts, injection text, tool arguments, API keys, or third-party pipeline objects.

## Tests

Run `python -m pytest tests/task4 -q`, then `python -m pytest -q`. Tests use a fake adapter and static trace data; some construct real AgentDojo pipelines offline, but no test calls a model endpoint. The historical web-ready fixture is `tests/contract_fixtures/task_4_result.json`.

## Coverage boundaries

All existing baseline, API-abuse, privilege-escalation, multi-step-hijack, context-leakage and DoS categories remain represented in the unfiltered quick and full subsets. This preserves business-task execution, attack injection, native tool calls, workspace isolation, trace parsing and error isolation. Removing ToolFilter does not guarantee nonempty tool calls: a valid model response can still fail to use tools and receive utility=0.

Do not equate multi-step tool workflows with comprehensive multi-turn dialogue testing, or security-code exfiltration with direct system-prompt leakage testing. The current DoS tests cover instruction-induced task abandonment, not network/resource exhaustion. Removing a defense does not itself fill these pre-existing competition-coverage gaps.
