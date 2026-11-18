import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { render } from "@testing-library/react";

import OnboardingCard from "@/components/OnboardingCard";
import { setRole } from "./helpers";

const getOnboarding = vi.fn();
const loadDemo = vi.fn();
vi.mock("@/lib/api", () => ({ api: { ops: { getOnboarding: (...a: unknown[]) => getOnboarding(...a), loadDemo: (...a: unknown[]) => loadDemo(...a) } } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const steps = (done: string[]) =>
  ["llm", "api_key", "first_event", "first_threat", "executor", "rules", "team"].map((id) => ({
    id,
    title: `Step ${id}`,
    done: done.includes(id),
    where: `where-${id}`,
  }));

const payload = (done: string[], extra = {}) => ({ steps: steps(done), completed: done.length, total: 7, next: "api_key", demo_loaded: false, ...extra });

describe("OnboardingCard", () => {
  beforeEach(() => {
    getOnboarding.mockReset();
    loadDemo.mockReset();
    setRole("admin");
  });

  it("lists every step, marks the done ones and says where to do the rest", async () => {
    getOnboarding.mockResolvedValue(payload(["llm"]));
    render(<OnboardingCard />);
    expect(await screen.findByText("Step api_key")).toBeInTheDocument();
    expect(screen.getByText("where-api_key")).toBeInTheDocument();
    expect(screen.queryByText("where-llm")).not.toBeInTheDocument(); // done steps do not repeat instructions
    expect(screen.getByText(/1 of 7 steps done/)).toBeInTheDocument();
    expect(screen.getAllByLabelText("done")).toHaveLength(1);
  });

  it("renders nothing once every required step is complete (the executor step is optional)", async () => {
    getOnboarding.mockResolvedValue(payload(["llm", "api_key", "first_event", "first_threat", "rules", "team"]));
    const { container } = render(<OnboardingCard />);
    await waitFor(() => expect(getOnboarding).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when the checklist cannot be loaded rather than showing a broken card", async () => {
    getOnboarding.mockRejectedValue(new Error("403"));
    const { container } = render(<OnboardingCard />);
    await waitFor(() => expect(getOnboarding).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("offers the demo campaign to admins only, and loads it on click", async () => {
    getOnboarding.mockResolvedValue(payload([]));
    loadDemo.mockResolvedValue({ accepted: 12, duplicates: 0, total_events: 12, note: "" });
    render(<OnboardingCard />);
    await userEvent.click(await screen.findByRole("button", { name: /synthetic attack campaign/i }));
    expect(loadDemo).toHaveBeenCalledTimes(1);
  });

  it("does not offer the demo to analysts or when it is already loaded", async () => {
    setRole("analyst");
    getOnboarding.mockResolvedValue(payload([]));
    const { unmount } = render(<OnboardingCard />);
    await screen.findByText("Step api_key");
    expect(screen.queryByRole("button", { name: /synthetic attack campaign/i })).not.toBeInTheDocument();
    unmount();
    setRole("admin");
    getOnboarding.mockResolvedValue(payload([], { demo_loaded: true }));
    render(<OnboardingCard />);
    await screen.findByText("Step api_key");
    expect(screen.queryByRole("button", { name: /synthetic attack campaign/i })).not.toBeInTheDocument();
  });

  it("can be dismissed and stays dismissed", async () => {
    getOnboarding.mockResolvedValue(payload([]));
    const { unmount, container } = render(<OnboardingCard />);
    await userEvent.click(await screen.findByLabelText("Dismiss getting started"));
    expect(container).toBeEmptyDOMElement();
    unmount();
    getOnboarding.mockClear();
    const again = render(<OnboardingCard />);
    expect(again.container).toBeEmptyDOMElement();
    expect(getOnboarding).not.toHaveBeenCalled();
  });
});
