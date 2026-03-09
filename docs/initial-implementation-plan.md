# Feasibility Analysis: Security Scan Triage via Threat Model Correlation

## Context

The idea is to build a tool that takes security scan outputs (SCA, SAST, Secrets) for a GitHub repo and correlates them against a `.tc.json` threat model file. Findings related to **mitigated** threats would have severity reduced; findings related to **unmitigated** threats retain original severity. The goal: surface what truly warrants human review.

## Verdict: Feasible, with caveats

The tool is **architecturally sound and buildable**. The `.tc.json` schema provides the right data structures. The main challenge is the **mapping layer** between scan findings and threat model entries — this is solvable but requires a deliberate strategy.

---

## What works well

### 1. The .tc.json data model is well-suited
- **Threats** have structured fields: `threatSource`, `prerequisites`, `threatAction`, `threatImpact`, `impactedAssets`, STRIDE tags, Priority
- **Mitigations** have clear status: `identified`, `inProgress`, `resolved`, `resolvedWillNotAction`
- **MitigationLinks** explicitly connect mitigations to threats
- **Threat status** distinguishes `identified` vs `resolved` vs `resolvedNotUseful`

### 2. "Is this threat mitigated?" is answerable
From the data model, a threat is effectively mitigated when:
- It has linked mitigations (via `mitigationLinks`) where the mitigation status is `resolved` or `resolvedWillNotAction`, OR
- The threat's own status is `threatResolved`

### 3. Reusable components from threat-composer
- **Zod schemas** for parsing/validating `.tc.json` files (`DataExchangeFormatSchema`, `validateData()`)
- **TypeScript types** for all entities (`TemplateThreatStatement`, `Mitigation`, `MitigationLink`, etc.)
- **STRIDE reference data** with category descriptions and security property mappings
- **Status constants** and color mappings
- **Metadata utilities** (`getMetadata()`) for extracting STRIDE/Priority from threat metadata
- All exported from `@aws/threat-composer` package

---

## The Core Challenge: Mapping Scan Findings → Threats

This is where the problem gets interesting. Security scan findings and threat model entries operate at different abstraction levels:

| Scan Type | Abstraction Level | Typical Output |
|-----------|-------------------|----------------|
| SCA | Dependency/CVE | "lodash 4.17.20 has CVE-2021-23337 (CWE-94, Critical)" |
| SAST | Code pattern | "SQL injection at src/db.ts:42 (CWE-89, High)" |
| Secrets | File/credential | "AWS key exposed in config.js (Critical)" |
| Threat Model | Architecture/design | "An internet-based actor can inject malicious SQL queries via the search API, which leads to unauthorized data access" |

### Mapping Strategies (from most to least practical)

#### Strategy A: STRIDE ↔ CWE Bridge (Recommended starting point)
- CWE IDs from SAST/SCA findings can be mapped to STRIDE categories via well-known mappings
- Threats in `.tc.json` already carry STRIDE metadata tags
- Example: CWE-89 (SQL Injection) → STRIDE "T" (Tampering) + "I" (Information Disclosure)
- A finding matches a threat if they share STRIDE categories
- **Pros**: Deterministic, no LLM needed, works today
- **Cons**: Coarse-grained — many findings will map to multiple threats

#### Strategy B: Keyword/semantic matching on threat statements
- Parse the `statement` field and match against CVE descriptions, CWE descriptions
- The threat `statement` will adhere to the Threat Grammar defined at https://catalog.workshops.aws/threatmodel/en-US/what-can-go-wrong/threat-grammar: "[threat source] [prerequisite] can [threat action], which leads to [threat impact], resulting in reduced [impacted goal] of [impacted asset]".
- Match `impactedAssets` against package names or file paths from findings
- **Pros**: More precise than STRIDE-only
- **Cons**: Brittle, depends on how threats are written

#### Strategy C: LLM-assisted matching
- Use an LLM to semantically compare each finding against each threat
- Most accurate but slowest and most expensive
- Could be a "precision" mode for ambiguous cases

#### Strategy D: Explicit tagging (requires schema extension)
- Add CWE IDs or scan rule IDs as tags/metadata on threats in the `.tc.json`
- Most precise, but requires upfront effort from threat modelers
- Could use existing `custom:` metadata keys (e.g., `custom:cwe` → ["CWE-89", "CWE-79"])

**Recommended approach**: Start with Strategy A (STRIDE↔CWE) as baseline, layer Strategy B for refinement, offer Strategy D as opt-in precision. Strategy C as optional enhancement.

---

## Scan Output Format Handling

Standard formats to support:

| Tool Category | Common Formats |
|---------------|---------------|
| SCA | SARIF, CycloneDX SBOM, Dependabot JSON, Snyk JSON, Trivy JSON |
| SAST | SARIF (CodeQL, Semgrep), SonarQube JSON |
| Secrets | SARIF, TruffleHog JSON, Gitleaks JSON |

**SARIF is the unifying format** — GitHub Code Scanning uses it, and most tools can output it. Starting with SARIF-only would cover the majority of use cases with a single parser.

---

## Severity Adjustment Logic

```
For each scan finding:
  1. Extract CWE/category from finding
  2. Map to STRIDE categories
  3. Find matching threats in .tc.json (by STRIDE + optional keyword matching)
  4. If no matching threat found:
     → Keep original severity (potential gap in threat model — flag this)
  5. If matching threat found AND threat is mitigated:
     → Reduce severity (e.g., Critical→Low, High→Info)
     → Add annotation: "Mitigated by: [mitigation content]"
  6. If matching threat found AND threat is NOT mitigated:
     → Keep original severity
     → Add annotation: "Related unmitigated threat: [threat statement]"
```

### Edge case: Secrets findings
Secrets findings (exposed credentials) are harder to map. These are almost always critical regardless of threat model status — an exposed AWS key is an exposed AWS key. Recommendation: **never reduce severity of secrets findings**, only annotate with related threat context.

---

## Practical Concerns

### What makes this effective
- Teams that already use threat-composer get immediate value from their existing threat models
- Reduces alert fatigue by deprioritizing findings where mitigations are already in place
- Surfaces gaps: findings with no matching threat indicate incomplete threat modeling
- The "gap detection" feature (findings that don't match any threat) might be more valuable than the severity reduction

### What could undermine effectiveness
- **Poor threat models**: If the `.tc.json` has vague threats or missing STRIDE tags, mapping quality degrades
- **Over-reduction risk**: A coarse mapping might incorrectly reduce severity of genuinely critical findings
- **False confidence**: Users might skip review of reduced-severity items that were incorrectly mapped
- **Stale threat models**: If the threat model isn't maintained, mitigations may be marked resolved when they're not

### Mitigations for these risks
- Always show the mapping rationale ("reduced because of threat T-42, mitigated by M-15")
- Never fully suppress findings — reduce severity but keep them visible
- Report a "mapping confidence" score
- Flag findings where mapping is ambiguous
- Warn when threat model hasn't been updated recently

---

## Suggested Architecture

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│  SARIF / Scan   │──▶│              │◀───│  .tc.json       │
│  Output Files   │    │  Correlator  │    │  Threat Model   │
└─────────────────┘    │              │    └─────────────────┘
                       │  1. Parse    │
                       │  2. Map      │
                       │  3. Evaluate │
                       │  4. Annotate │
                       └──────┬───────┘
                              │
                       ┌──────▼───────┐
                       │  Triaged     │
                       │  Report      │
                       │  (SARIF +    │
                       │   annotations│
                       └──────────────┘
```

### Key components
1. **Scan Parser**: SARIF → normalized findings (reuse existing SARIF libraries)
2. **Threat Model Parser**: .tc.json → structured model (reuse `@aws/threat-composer` types + `validateData()`)
3. **CWE↔STRIDE Mapper**: Static mapping table (well-documented in MITRE resources)
4. **Correlator**: Match findings to threats, check mitigation status
5. **Report Generator**: Annotated SARIF or custom report with severity adjustments

### Could run as
- CLI tool (most useful for CI/CD integration)
- GitHub Action (natural fit for PR workflows)
- Could output modified SARIF that GitHub Code Scanning understands

---

## On Repurposing threat-composer-ai Agents

The `packages/threat-composer-ai/` contains 8 AI agents that form a **generation pipeline**: analyze code → extract architecture → identify dataflows → generate threats → suggest mitigations → assemble .tc.json. They are designed to **create** threat models from source code.

Your tool does the **inverse** — it takes an existing threat model and correlates it against scan findings. The existing agents don't fit this direction.

### What's worth borrowing

1. **STRIDE reasoning patterns from the Threats agent** (`agents/threats.py`) — its prompt contains excellent domain knowledge about how STRIDE categories map to specific threat patterns. This informs your CWE↔STRIDE mapping table and any LLM-assisted matching prompt.

2. **The agent framework pattern** — if you implement LLM-assisted matching (Strategy C), write a **new** purpose-built "correlation agent" inspired by their structure: take a batch of findings + the threat model as context, return structured mapping decisions. Don't repurpose the generation agents.

3. **Schema validation patterns** — the agents use the same Zod schemas and validation utilities recommended above.

### Verdict: Don't repurpose, but reference

Wrapping the existing generation agents into a correlation workflow would add unnecessary complexity and API costs (they'd want to regenerate threats from code rather than just compare findings against existing ones). A simpler, deterministic mapping layer (Strategies A+B+D) handles 80% of cases. An optional LLM call for ambiguous matches (Strategy C) should be a focused, single-purpose prompt — not a full agent pipeline.

---

## Design Spec: Detailed Component Design

### Component 1: SARIF Parser (`sarif-parser`)

**Input**: One or more SARIF v2.1.0 files
**Output**: Normalized `ScanFinding[]`

```typescript
interface ScanFinding {
  id: string;                    // SARIF result GUID or generated
  source: 'sca' | 'sast' | 'secrets';  // Inferred from tool name/rules
  tool: string;                  // e.g., "CodeQL", "Trivy", "Gitleaks"
  ruleId: string;                // SARIF rule ID
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwes: string[];                // e.g., ["CWE-89"] — extracted from SARIF rule metadata
  description: string;           // Finding message
  location?: {
    file: string;
    startLine?: number;
  };
  cveId?: string;                // For SCA findings
  packageName?: string;          // For SCA findings
  secretType?: string;           // For secrets findings
  raw: object;                   // Original SARIF result for passthrough
}
```

**Key SARIF extraction points**:
- `run.tool.driver.name` → tool name
- `result.ruleId` → rule ID
- `run.tool.driver.rules[].properties.tags[]` → CWE IDs (look for "external/cwe/cwe-89" pattern)
- `result.level` → severity mapping (error=high, warning=medium, note=low)
- `result.locations[].physicalLocation` → file/line

### Component 2: Threat Model Parser (`tc-parser`)

**Input**: `.tc.json` file path
**Output**: Structured `ThreatModel`

```typescript
interface ThreatModel {
  threats: ParsedThreat[];
  mitigations: ParsedMitigation[];
  mitigationLinks: MitigationLink[];
  assumptionLinks: AssumptionLink[];
}

interface ParsedThreat {
  id: string;
  numericId: number;
  statement: string;
  status: string;
  stride: string[];           // ["S", "T"] etc.
  priority: string;           // "High", "Medium", "Low"
  impactedAssets: string[];
  impactedGoal: string[];
  threatSource: string;
  threatAction: string;
  threatImpact: string;
  isMitigated: boolean;       // Computed from links + statuses
  linkedMitigations: ParsedMitigation[];  // Resolved from links
  metadata: string;
}

interface ParsedMitigation {
  id: string;
  numericId: number;
  content: string;
  status: string;
}
```

**Mitigation resolution logic**:
```
threat.isMitigated =
  threat.status === 'threatResolved'
  OR (
    threat has at least one mitigationLink
    AND ALL linked mitigations have status 'mitigationResolved' or 'mitigationResolvedWillNotAction'
  )
```

### Component 3: CWE↔STRIDE Mapper (`cwe-stride-map`)

A static mapping table. Key mappings (subset):

| CWE Category | Example CWEs | STRIDE Categories |
|---------------|-------------|-------------------|
| Injection | CWE-89 (SQLi), CWE-79 (XSS), CWE-94 (Code Injection) | T, I |
| Auth/AuthZ | CWE-287 (Auth Bypass), CWE-862 (Missing AuthZ) | S, E |
| Crypto | CWE-327 (Broken Crypto), CWE-326 (Weak Encryption) | I, T |
| Info Exposure | CWE-200 (Info Leak), CWE-532 (Log Exposure) | I |
| DoS | CWE-400 (Resource Exhaustion) | D |
| Input Validation | CWE-20 (Improper Input Validation) | T |
| SSRF/Path | CWE-918 (SSRF), CWE-22 (Path Traversal) | S, I, E |
| Deserialization | CWE-502 (Deserialization) | T, E |
| Secrets | (no CWE — detected by pattern) | I |

**Source**: MITRE CWE database + STRIDE methodology literature. The mapping should cover the ~50 most common CWEs from SAST/SCA tools.

For findings **without** CWEs (common in secrets scanners), default to STRIDE "I" (Information Disclosure).

### Component 4: Correlator (`correlator`)

The core matching engine. For each finding:

```
function correlate(finding: ScanFinding, model: ThreatModel): CorrelationResult {
  1. Map finding.cwes → STRIDE categories via cwe-stride-map
  2. Find candidate threats where threat.stride overlaps with finding's STRIDE categories
  3. Score candidates:
     - +3 if STRIDE category match
     - +2 if impactedAssets contains finding.packageName or finding.location.file
     - +2 if threat statement keywords match finding description
     - +1 if threat priority aligns with finding severity
  4. Rank candidates by score, take top match if score ≥ threshold (e.g., 3)
  5. If match found: check match.isMitigated
  6. Return correlation result
}
```

```typescript
interface CorrelationResult {
  finding: ScanFinding;
  matchedThreat: ParsedThreat | null;
  matchedMitigations: ParsedMitigation[];
  confidence: 'high' | 'medium' | 'low' | 'none';
  adjustedSeverity: string;      // Original or reduced
  originalSeverity: string;
  reason: string;                 // Human-readable explanation
  isGap: boolean;                 // True if no threat matches (gap in threat model)
}
```

**Severity reduction rules**:
- Secrets findings: **never reduce** (always keep original)
- Mitigated threat match with high confidence: reduce by 3 levels (Critical→Low, High→Info)
- Mitigated threat match with medium confidence: reduce by 1 level (Critical→High)
- Unmitigated threat match: keep original severity
- No match (gap): keep original severity, flag as gap

### Component 5: Report Generator (`reporter`)

**Output formats** (start with these two):

1. **Annotated SARIF**: Modified SARIF with:
   - `result.level` adjusted per severity reduction
   - `result.properties.originalSeverity` preserved
   - `result.properties.threatModelCorrelation` added with match details
   - Compatible with GitHub Code Scanning upload

2. **Summary Report** (Markdown or JSON):
   - Findings grouped by: unmitigated (action required), mitigated (reduced), gaps (no threat coverage)
   - Statistics: total findings, reduced count, gap count
   - Threat model coverage: % of findings with matching threats

### Component 6 (Optional): LLM Correlation Agent (`llm-correlator`)

For ambiguous matches (confidence = 'low' or multiple candidates with similar scores):

```
Prompt template:
"Given this security scan finding:
  Tool: {finding.tool}
  Rule: {finding.ruleId}
  CWEs: {finding.cwes}
  Severity: {finding.severity}
  Description: {finding.description}
  Location: {finding.location}

And these candidate threats from the threat model:

{for each candidate:}
  Threat T-{candidate.numericId}:
    Statement: {candidate.statement}
    STRIDE: {candidate.stride}
    Priority: {candidate.priority}
    Impacted Assets: {candidate.impactedAssets}
    Metadata: {candidate.metadata}
    Mitigation Status: {'mitigated' if candidate.isMitigated else 'unmitigated'}
    Linked Mitigations: {candidate.linkedMitigations[].content}

Which threat (if any) does this finding most closely relate to?
Consider the threat metadata for additional context — it may contain comments,
custom annotations, or source references that clarify the threat's scope.
Return the threat ID and confidence level (high/medium/low), or 'none' if no match."
```

The `metadata` field on threats is a free-text key-value store that may contain comments, custom annotations (`custom:*` keys), or source pack references. This context can be valuable for disambiguation — e.g., a `Comments` metadata entry might describe specific technologies or attack vectors that help the LLM match more precisely.

- Call only for ambiguous cases (not every finding)
- Cache results for identical finding+threat combinations
- Works with Claude API or any LLM

---

## Implementation Recommendations

### Language choice
**Python** — aligns with the security tooling ecosystem and the `threat-composer-ai` agent patterns. Use Pydantic for schema validation (analogous to Zod). The `.tc.json` schema can be translated to Pydantic models directly.

### Project structure (fresh repo)
```
tc-json-triage/
├── src/
│   └── tc_json_triage/
│       ├── __init__.py
│       ├── cli.py                # CLI entry point (Click or argparse)
│       ├── parsers/
│       │   ├── __init__.py
│       │   ├── sarif.py          # SARIF parser
│       │   └── threat_model.py   # .tc.json parser (Pydantic models)
│       ├── mapping/
│       │   ├── __init__.py
│       │   ├── cwe_stride.py     # Static CWE↔STRIDE mapping table
│       │   └── correlator.py     # Main correlation engine
│       ├── output/
│       │   ├── __init__.py
│       │   ├── sarif_annotator.py # Annotated SARIF output
│       │   └── summary.py        # Summary report
│       └── llm/                   # Optional
│           ├── __init__.py
│           └── correlator.py     # LLM-assisted matching
├── data/
│   └── cwe_stride_map.json      # Static mapping data
├── tests/
│   ├── fixtures/                  # Sample SARIF + .tc.json files
│   └── ...
├── pyproject.toml
└── README.md
```

### CLI interface
```bash
# Basic usage
tc-json-triage --threat-model app.tc.json --sarif scan-results.sarif

# Multiple scan files
tc-json-triage --threat-model app.tc.json --sarif sca.sarif --sarif sast.sarif --sarif secrets.sarif

# Output formats
tc-json-triage --threat-model app.tc.json --sarif scan.sarif --output-format sarif --output triaged.sarif
tc-json-triage --threat-model app.tc.json --sarif scan.sarif --output-format summary --output report.md

# With LLM-assisted matching (requires ANTHROPIC_API_KEY env var)
tc-json-triage --threat-model app.tc.json --sarif scan.sarif --llm-assist
```

### Key Python dependencies
- `pydantic` — .tc.json schema validation and data models
- `click` — CLI framework
- `anthropic` — Claude API for LLM-assisted matching (optional)
- `pytest` — testing

### GitHub Action usage
```yaml
- uses: your-org/tc-json-triage-action@v1
  with:
    threat-model: threat-model.tc.json
    sarif-files: |
      sca-results.sarif
      sast-results.sarif
    output: triaged.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: triaged.sarif
```

---

## Verification / Testing Strategy

1. **Unit tests**: CWE→STRIDE mapping coverage, mitigation status resolution, severity reduction logic
2. **Integration tests**: Full pipeline with sample SARIF + .tc.json fixtures
3. **Test fixtures needed**:
   - A `.tc.json` with mixed mitigated/unmitigated threats across STRIDE categories
   - SARIF files from Gosec, Grype, and Trufflehog with known CWEs
   - Expected correlation results for each combination
4. **Edge cases**: findings with no CWE, threats with no STRIDE tags, empty threat model, secrets findings

---

## Summary

| Aspect | Assessment |
|--------|-----------|
| Data model suitability | Strong — .tc.json has the right structures |
| Reusable components | Good — types, validation, STRIDE data from `@aws/threat-composer` |
| AI agents reuse | Reference patterns only — don't repurpose generation agents for correlation |
| Mapping accuracy | Moderate — STRIDE↔CWE gives coarse matching; needs refinement layers |
| Implementation effort | Medium — SARIF parsing + mapping logic + report generation |
| Risk of false negatives | Moderate — mitigate with confidence scores and never-suppress policy |
| Value proposition | High for teams already using threat-composer |
