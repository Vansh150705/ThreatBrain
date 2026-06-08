import { setToken, clearToken } from "@/lib/api";
import { supabase } from "./client";

// Sign in with email + password
export async function signIn(email: string, password: string) {
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });
  if (error) throw error;
  if (data.session?.access_token) {
    setToken(data.session.access_token);
    await supabase.realtime.setAuth(data.session.access_token);
  }
  return data;
}

// Sign out — clear both Supabase and our API client token
export async function signOut() {
  await supabase.auth.signOut();
  clearToken();
}

// Get current session (refreshes the JWT if needed)
export async function getSession() {
  const { data, error } = await supabase.auth.getSession();
  if (error) throw error;
  if (data.session?.access_token) {
    setToken(data.session.access_token);
    await supabase.realtime.setAuth(data.session.access_token);
  }
  return data.session;
}

// Sync token whenever Supabase refreshes it (every ~1 hour)
supabase.auth.onAuthStateChange((_event, session) => {
  if (session?.access_token) {
    setToken(session.access_token);
    supabase.realtime.setAuth(session.access_token);
  } else {
    clearToken();
  }
});