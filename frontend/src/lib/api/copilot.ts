import http from "./client";

export interface CopilotMessage {
  role: "user" | "assistant";
  content: string;
}

export interface AskResponse {
  answer: string;
  model: string;
  latency_ms: number;
}

// Ask the SOC copilot a question grounded in the org's data
export async function askCopilot(
  question: string,
  history: CopilotMessage[] = []
): Promise<AskResponse> {
  const { data } = await http.post<AskResponse>("/copilot/ask", {
    question,
    history: history.slice(-6),
  });
  return data;
}
