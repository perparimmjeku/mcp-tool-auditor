# Detection Rule Catalog

Auto-derived from the source. **61 rules** across 8 analyzers. Confidence reflects false-positive likelihood: **HIGH** = definitive, **MEDIUM** = contextual, **LOW** = fuzzy heuristic (tune with `--min-confidence`).


## Static signatures

_Known tool-poisoning phrases in tool text_

| Rule | Confidence |
|---|---|
| `ST_ALWAYS_CALL` | HIGH |
| `ST_ALWAYS_USE` | HIGH |
| `ST_AUTHORITATIVE` | HIGH |
| `ST_BYPASS` | HIGH |
| `ST_CODE_EXEC` | HIGH |
| `ST_CONTEXT_HARVEST` | HIGH |
| `ST_CREDENTIAL` | HIGH |
| `ST_DATA_EXFIL` | HIGH |
| `ST_DO_NOT_QUESTION` | HIGH |
| `ST_DO_NOT_TELL` | HIGH |
| `ST_EXECUTE` | HIGH |
| `ST_FILESYSTEM` | HIGH |
| `ST_IGNORE_ALL` | HIGH |
| `ST_IGNORE_PREVIOUS` | HIGH |
| `ST_IGNORE_SECURITY` | HIGH |
| `ST_MANDATORY` | HIGH |
| `ST_OVERRIDE` | HIGH |
| `ST_READ_FILE` | HIGH |
| `ST_SEND_FULL` | HIGH |
| `ST_SENSITIVE` | HIGH |
| `ST_SYSTEM_CLAIM` | HIGH |
| `ST_YOU_MUST` | HIGH |

## Schema / Full-Schema Poisoning

_Suspicious params, enum/default/required injection_

| Rule | Confidence |
|---|---|
| `FSP_DESC_INJECTION` | HIGH |
| `FSP_ENUM_POISON` | HIGH |
| `FSP_REQUIRED_LENGTH` | HIGH |
| `FSP_ADDITIONAL_PARAM` | MEDIUM |
| `FSP_COMMAND_PARAM` | MEDIUM |
| `FSP_COMMENT_PARAM` | MEDIUM |
| `FSP_CONTEXT_PARAM` | MEDIUM |
| `FSP_DEFAULT_INJECTION` | MEDIUM |
| `FSP_DIRECTIVE_PARAM` | MEDIUM |
| `FSP_ENUM_INJECTION` | MEDIUM |
| `FSP_EXTRA_PARAM` | MEDIUM |
| `FSP_FEEDBACK_PARAM` | MEDIUM |
| `FSP_INJECTION_PARAM` | MEDIUM |
| `FSP_INSTRUCTION_PARAM` | MEDIUM |
| `FSP_MISSING_REQUIRED` | MEDIUM |
| `FSP_NOTE_PARAM` | MEDIUM |
| `FSP_OVERRIDE_PARAM` | MEDIUM |
| `FSP_PARAM_NAME` | MEDIUM |
| `FSP_REMARK_PARAM` | MEDIUM |
| `FSP_SIDENOTE` | MEDIUM |
| `FSP_SYSTEM_PROMPT_PARAM` | MEDIUM |

## Heuristics

_Length, imperative/agency language, hidden Unicode_

| Rule | Confidence |
|---|---|
| `HEUR_UNICODE_HIDDEN` | HIGH |
| `HEUR_AUTHORITY_SPOOF` | MEDIUM |
| `HEUR_AGENCY` | LOW |
| `HEUR_DESC_LENGTH` | LOW |
| `HEUR_IMPERATIVE` | LOW |
| `HEUR_PARAM_DESC_LONG` | LOW |

## Schema hygiene

_Permissive/untyped parameters_

| Rule | Confidence |
|---|---|
| `SCHEMA_GENERIC_TYPE` | LOW |
| `SCHEMA_UNTYPED` | LOW |

## Rug-pull

_Fingerprint drift vs. registered baseline_

| Rule | Confidence |
|---|---|
| `RUGPULL_FINGERPRINT_MISMATCH` | HIGH |
| `RUGPULL_NEW_TOOL` | MEDIUM |
| `RUGPULL_NO_BASELINE` | MEDIUM |
| `RUGPULL_REMOVED_TOOL` | MEDIUM |

## Behavioral / ATPA

_Runtime response analysis_

| Rule | Confidence |
|---|---|
| `BEHAV_ATPA_TRANSITION` | HIGH |
| `BEHAV_OUTPUT_INJECTION` | HIGH |
| `BEHAV_CALL_ERROR` | MEDIUM |
| `BEHAV_RESPONSE_DIVERGENCE` | LOW |

## Source-scan

_Shell-injection sinks in MCP server code_

| Rule | Confidence |
|---|---|
| `SRC_SHELL_INJECTION` | HIGH |

## Operational

_Scan errors (not a vulnerability)_

| Rule | Confidence |
|---|---|
| `SCAN_FAILED` | MEDIUM |
