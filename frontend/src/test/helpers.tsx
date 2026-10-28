import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { render } from "@testing-library/react";

import { useUserStore } from "@/store/useUserStore";
import type { MeResponse } from "@/lib/api";

export function renderWithRouter(ui: ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

export function setRole(role: "viewer" | "analyst" | "admin" | "owner", id = "self-user") {
  useUserStore.setState({
    profile: { id, role, status: "active", email: "me@example.com", full_name: "Me", organization_id: "org-1" } as MeResponse,
    loading: false,
    error: null,
  });
}
