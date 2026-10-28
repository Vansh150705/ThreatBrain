import http from "./client";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface BuiltinRule {
  id: string;
  name: string;
  severity: Severity;
  confidence: number;
  tactics: string[];
  techniques: string[];
  tags: string[];
  tuning: string;
  tests: number;
  enabled: boolean;
  severity_override: Severity | null;
  override_reason: string | null;
}

export interface CustomRule {
  id: string;
  rule_key: string;
  name: string;
  severity: Severity;
  confidence: number;
  techniques: string[];
  tactics: string[];
  status: "draft" | "enabled" | "disabled";
  origin: "native" | "sigma" | "proposal";
  version: number;
  match: Record<string, unknown>;
  tests: Array<{ name?: string; event: Record<string, unknown>; expect_match: boolean }>;
  tuning_guidance?: string | null;
}

export interface RulesResponse {
  version: string;
  builtin: BuiltinRule[];
  custom: CustomRule[];
}

export interface CoverageTactic {
  id: string;
  name: string;
  techniques_in_catalog: number;
  covered: number;
  uncovered: string[];
}

export interface Coverage {
  rule_version: string;
  techniques: Record<string, string[]>;
  tactics: CoverageTactic[];
}

export interface RuleDefinitionInput {
  rule_key: string;
  name: string;
  severity: Severity;
  confidence?: number;
  techniques?: string[];
  match: Record<string, unknown>;
  tests?: CustomRule["tests"];
  description?: string;
}

export interface ValidationResult {
  valid: boolean;
  tactics: string[];
  tests: Array<{ name: string; expected: boolean; matched: boolean; passed: boolean }>;
  tests_passed: boolean;
  has_positive_and_negative: boolean;
  attack_warnings: string[];
}

export interface TuningResult {
  run_id: string;
  recommendation: "tune" | "disable" | "keep";
  assessment: string;
  rationale: string;
  changes: string[];
  stored_rule_id: string | null;
  evidence: Record<string, number>;
  verification: {
    accepted: boolean | null;
    reasons: string[];
    measurements: Record<string, number>;
  };
}

export const listRules = async (): Promise<RulesResponse> => (await http.get<RulesResponse>("/rules")).data;
export const getCoverage = async (): Promise<Coverage> => (await http.get<Coverage>("/rules/coverage")).data;

export const setBuiltinOverride = async (
  ruleKey: string,
  body: { enabled: boolean; severity_override?: Severity | null; reason?: string }
) => (await http.put(`/rules/builtin/${encodeURIComponent(ruleKey)}/override`, body)).data;

export const validateRule = async (rule: RuleDefinitionInput): Promise<ValidationResult> =>
  (await http.post<ValidationResult>("/rules/validate", rule)).data;

export const createRule = async (rule: RuleDefinitionInput): Promise<CustomRule> =>
  (await http.post<CustomRule>("/rules", rule)).data;

export const setRuleStatus = async (id: string, status: CustomRule["status"]): Promise<CustomRule> =>
  (await http.post<CustomRule>(`/rules/${id}/status`, { status })).data;

export const deleteRule = async (id: string): Promise<void> => {
  await http.delete(`/rules/${id}`);
};

export const convertSigma = async (sigma: string) =>
  (await http.post<{ rule: RuleDefinitionInput; warnings: string[] }>("/rules/sigma/convert", { sigma })).data;

export const importSigma = async (sigma: string) =>
  (await http.post<{ rule: CustomRule; warnings: string[] }>("/rules/sigma/import", { sigma })).data;

export const proposeTuning = async (ruleKey: string): Promise<TuningResult> =>
  (await http.post<TuningResult>(`/rules/${encodeURIComponent(ruleKey)}/tuning-proposal`)).data;
