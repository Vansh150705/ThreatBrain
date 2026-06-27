import { create } from "zustand";
import { persist } from "zustand/middleware";

interface UIState {
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  mobileNavOpen: boolean;
  openMobileNav: () => void;
  closeMobileNav: () => void;
}

// UI preferences that persist across reloads
export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      toggleSidebar: () =>
        set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      setSidebarCollapsed: (collapsed: boolean) =>
        set({ sidebarCollapsed: collapsed }),
      mobileNavOpen: false,
      openMobileNav: () => set({ mobileNavOpen: true }),
      closeMobileNav: () => set({ mobileNavOpen: false }),
    }),
    {
      name: "threatbrain.ui",
      // Only the collapse preference should survive reloads; the mobile
      // drawer always starts closed.
      partialize: (state) => ({ sidebarCollapsed: state.sidebarCollapsed }),
    }
  )
);