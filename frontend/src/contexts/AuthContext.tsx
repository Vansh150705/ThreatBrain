import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import type { Session } from "@supabase/supabase-js";

import { supabase, getSession } from "@/lib/supabase";
import { useUserStore } from "@/store/useUserStore";

interface AuthContextValue {
  session: Session | null;
  loading: boolean;
}

const AuthContext = createContext<AuthContextValue>({
  session: null,
  loading: true,
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const fetchProfile = useUserStore((s) => s.fetchProfile);
  const clearProfile = useUserStore((s) => s.clearProfile);

  useEffect(() => {
    // On mount: check for an existing session
    getSession()
      .then((s) => {
        setSession(s);
        if (s) fetchProfile();
      })
      .catch(() => setSession(null))
      .finally(() => setLoading(false));

    // Subscribe to auth state changes
    const { data: sub } = supabase.auth.onAuthStateChange((_evt, s) => {
      setSession(s);
      if (s) {
        fetchProfile();
      } else {
        clearProfile();
      }
    });
    return () => sub.subscription.unsubscribe();
  }, [fetchProfile, clearProfile]);

  return (
    <AuthContext.Provider value={{ session, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}