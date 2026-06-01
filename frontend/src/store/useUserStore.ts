import { create } from "zustand";
import { persist } from "zustand/middleware";

import { api, type MeResponse } from "@/lib/api";

interface UserState {
  // Profile data
  profile: MeResponse | null;
  loading: boolean;
  error: string | null;

  // Actions
  fetchProfile: () => Promise<void>;
  clearProfile: () => void;
}

// Zustand store with localStorage persistence
export const useUserStore = create<UserState>()(
  persist(
    (set) => ({
      profile: null,
      loading: false,
      error: null,

      fetchProfile: async () => {
        set({ loading: true, error: null });
        try {
          const profile = await api.me.getMe();
          set({ profile, loading: false });
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          set({ error: message, loading: false, profile: null });
        }
      },

      clearProfile: () => set({ profile: null, error: null }),
    }),
    {
      name: "threatbrain.user", // localStorage key
      partialize: (state) => ({ profile: state.profile }), // only persist profile
    }
  )
);