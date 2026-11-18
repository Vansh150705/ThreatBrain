import http from "./client";

export interface LogFinding {
  title: string;
  detail: string;
  severity: string;
  evidence_lines: number[];
  mitre_techniques: string[];
  verified: boolean;
}

export interface LogAnalysisVerdict {
  summary: string;
  severity: string;
  confidence: number;
  entities: Record<"ips" | "users" | "hosts" | "domains" | "hashes", string[]>;
  findings: LogFinding[];
  suggested_detections: string[];
  reasoning: string;
  rule_hits: Array<{ rule_id: string; name: string; severity: string; line: number; techniques: string[] }>;
  lines_analyzed: number;
}

export interface LogAnalysisResponse {
  run_id: string;
  verdict: LogAnalysisVerdict;
  model: string;
  latency_ms: number;
  total_tokens: number;
}

export async function analyzeLogs(text: string, sourceHint?: string): Promise<LogAnalysisResponse> {
  const { data } = await http.post<LogAnalysisResponse>(
    "/agents/log-analysis/analyze",
    { text, source_hint: sourceHint || undefined },
    { timeout: 120_000 }
  );
  return data;
}
