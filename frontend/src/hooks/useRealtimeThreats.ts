import { useEffect, useRef, useState, useCallback } from "react";
import type { RealtimeChannel } from "@supabase/supabase-js";

import { supabase } from "@/lib/supabase";
import { useUserStore } from "@/store/useUserStore";

const REALTIME_DEBUG = import.meta.env.DEV || import.meta.env.VITE_REALTIME_DEBUG === "true";
if (REALTIME_DEBUG) console.log("[Realtime module] loaded at", new Date().toISOString());

// Types

export interface RealtimeThreatRow {
  id: string;
  short_id: string;
  organization_id?: string;
  title: string;
  description?: string | null;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status:
    | "open"
    | "investigating"
    | "contained"
    | "resolved"
    | "closed"
    | "false_positive";
  confidence: number;
  risk_score: number | null;
  mitre_tactics: string[];
  mitre_techniques: string[];
  source_ips: string[];
  target_ips: string[];
  detected_at: string;
  created_at: string;
  updated_at: string;

  _isNew?: boolean;
}

export type RealtimeStatus = "connecting" | "live" | "disconnected" | "error";

interface UseRealtimeThreatsOptions {
  /** Initial threats to seed the list with (typically from the REST API). */
  initial?: RealtimeThreatRow[];
  /** Hard cap on the in-memory list (prevents leaks on busy orgs). */
  maxItems?: number;
  /** How long the `_isNew` flag stays true on freshly inserted rows. */
  highlightMs?: number;
  /** Disable the subscription (useful for tests or when org is loading). */
  enabled?: boolean;
}

interface UseRealtimeThreatsResult {
  threats: RealtimeThreatRow[];
  status: RealtimeStatus;
  /** Manually merge fetched threats (e.g. after pagination). */
  setThreats: React.Dispatch<React.SetStateAction<RealtimeThreatRow[]>>;
  /** Count of threats that arrived since the hook mounted. */
  newCount: number;
  /** Reset the new-arrival counter (e.g. when the user scrolls to top). */
  acknowledgeNew: () => void;
}

// Hook

export function useRealtimeThreats(
  options: UseRealtimeThreatsOptions = {}
): UseRealtimeThreatsResult {
  if (REALTIME_DEBUG) console.log("[Realtime hook] useRealtimeThreats entered, options=", options);
  const {
    initial = [],
    maxItems = 100,
    highlightMs = 3000,
    enabled = true,
  } = options;

  const profile = useUserStore((s) => s.profile);
  const orgId =
    profile?.organization?.id ??
    (profile as { organization_id?: string })?.organization_id ??
    (profile as { org?: { id?: string } })?.org?.id ??
    (profile as { org_id?: string })?.org_id ??
    null;
  if (REALTIME_DEBUG) console.log(
    "[Realtime hook] orgId resolution — profile keys:",
    profile ? Object.keys(profile) : "no profile yet",
    "resolved orgId:",
    orgId
  );

  const [threats, setThreats] = useState<RealtimeThreatRow[]>(initial);
  const [status, setStatus] = useState<RealtimeStatus>("connecting");
  const [newCount, setNewCount] = useState(0);

  // Track the live channel so we can clean up on unmount / org change.
  const channelRef = useRef<RealtimeChannel | null>(null);

  // Track timers that clear `_isNew` flags so we can cancel them on unmount.
  const highlightTimersRef = useRef<Map<string, number>>(new Map());

  const acknowledgeNew = useCallback(() => setNewCount(0), []);

  useEffect(() => {
    if (REALTIME_DEBUG) console.log(`[Realtime:threats] orgId=${orgId} enabled=${enabled}`);

    if (!enabled || !orgId) {
      setStatus("connecting");
      return;
    }

    setStatus("connecting");

    // One channel per org. Supabase Realtime filter syntax requires `eq.<value>`.
    if (REALTIME_DEBUG) console.log("[Realtime] About to create channel for orgId:", orgId, "table: threats");
    if (REALTIME_DEBUG) console.log("[Realtime] Supabase URL:", import.meta.env.VITE_SUPABASE_URL);
    const channel = supabase
      .channel(`threats:org:${orgId}`)
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table: "threats",
          filter: `organization_id=eq.${orgId}`,
        },
        (payload) => {
          const row = payload.new as RealtimeThreatRow;
          if (REALTIME_DEBUG) console.log(`[Realtime:threats] INSERT received`, row);

          // Guard against echoes / duplicates.
          setThreats((prev) => {
            if (prev.some((t) => t.id === row.id)) return prev;
            const next = [{ ...row, _isNew: true }, ...prev];
            return next.length > maxItems ? next.slice(0, maxItems) : next;
          });

          setNewCount((c) => c + 1);

          // Schedule removal of the _isNew flag after highlightMs.
          const timerId = window.setTimeout(() => {
            setThreats((prev) =>
              prev.map((t) =>
                t.id === row.id ? { ...t, _isNew: false } : t
              )
            );
            highlightTimersRef.current.delete(row.id);
          }, highlightMs);

          highlightTimersRef.current.set(row.id, timerId);
        }
      )
      .subscribe((subStatus, err) => {
        if (REALTIME_DEBUG) console.log("[Realtime] subscribe callback fired. subStatus=", subStatus, "err=", err);
        if (REALTIME_DEBUG) console.log(`[Realtime:threats] channel status → ${subStatus}`);
        if (subStatus === "SUBSCRIBED") setStatus("live");
        else if (subStatus === "CHANNEL_ERROR") setStatus("error");
        else if (subStatus === "TIMED_OUT") setStatus("error");
        else if (subStatus === "CLOSED") setStatus("disconnected");
      });

    channelRef.current = channel;

    return () => {
      // Cancel pending highlight clears.
      for (const timerId of highlightTimersRef.current.values()) {
        window.clearTimeout(timerId);
      }
      highlightTimersRef.current.clear();

      if (channelRef.current) {
        supabase.removeChannel(channelRef.current);
        channelRef.current = null;
      }
    };
  }, [enabled, orgId, maxItems, highlightMs]);

  return {
    threats,
    status,
    setThreats,
    newCount,
    acknowledgeNew,
  };
}

export interface RealtimeBaseRow {
  id: string;
  organization_id: string;
  _isNew?: boolean;
}

interface UseRealtimeRowsOptions<T> {
  /** Postgres table name (must be in the supabase_realtime publication). */
  table: string;
  /** Seed list (e.g. from a REST fetch). */
  initial?: T[];
  /** Cap on in-memory rows. */
  maxItems?: number;
  /** How long `_isNew` stays true after an INSERT arrives. */
  highlightMs?: number;
  /** Disable while parent data is loading. */
  enabled?: boolean;
}

interface UseRealtimeRowsResult<T> {
  rows: T[];
  status: RealtimeStatus;
  setRows: React.Dispatch<React.SetStateAction<T[]>>;
  newCount: number;
  acknowledgeNew: () => void;
}


export function useRealtimeRows<T extends RealtimeBaseRow>(
  options: UseRealtimeRowsOptions<T>
): UseRealtimeRowsResult<T> {
  if (REALTIME_DEBUG) console.log("[Realtime hook] useRealtimeRows entered, options=", options);
  const {
    table,
    initial = [],
    maxItems = 100,
    highlightMs = 3000,
    enabled = true,
  } = options;

  const profile = useUserStore((s) => s.profile);
  const orgId =
    profile?.organization?.id ??
    (profile as { organization_id?: string })?.organization_id ??
    (profile as { org?: { id?: string } })?.org?.id ??
    (profile as { org_id?: string })?.org_id ??
    null;
  if (REALTIME_DEBUG) console.log(
    "[Realtime hook] orgId resolution — profile keys:",
    profile ? Object.keys(profile) : "no profile yet",
    "resolved orgId:",
    orgId
  );

  const [rows, setRows] = useState<T[]>(initial);
  const [status, setStatus] = useState<RealtimeStatus>("connecting");
  const [newCount, setNewCount] = useState(0);

  const channelRef = useRef<RealtimeChannel | null>(null);
  const highlightTimersRef = useRef<Map<string, number>>(new Map());

  const acknowledgeNew = useCallback(() => setNewCount(0), []);

  useEffect(() => {
    if (REALTIME_DEBUG) console.log(`[Realtime:${table}] orgId=${orgId} enabled=${enabled}`);

    if (!enabled || !orgId) {
      setStatus("connecting");
      return;
    }

    setStatus("connecting");

    if (REALTIME_DEBUG) console.log(`[Realtime] About to create channel for orgId:`, orgId, `table: ${table}`);
    if (REALTIME_DEBUG) console.log("[Realtime] Supabase URL:", import.meta.env.VITE_SUPABASE_URL);
    const channel = supabase
      .channel(`${table}:org:${orgId}`)
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table,
          filter: `organization_id=eq.${orgId}`,
        },
        (payload) => {
          const row = payload.new as T;
          if (REALTIME_DEBUG) console.log(`[Realtime:${table}] INSERT received`, row);
          setRows((prev) => {
            if (prev.some((r) => r.id === row.id)) return prev;
            const next = [{ ...row, _isNew: true }, ...prev];
            return next.length > maxItems ? next.slice(0, maxItems) : next;
          });
          setNewCount((c) => c + 1);

          const timerId = window.setTimeout(() => {
            setRows((prev) =>
              prev.map((r) => (r.id === row.id ? { ...r, _isNew: false } : r))
            );
            highlightTimersRef.current.delete(row.id);
          }, highlightMs);
          highlightTimersRef.current.set(row.id, timerId);
        }
      )
      .subscribe((subStatus, err) => {
        if (REALTIME_DEBUG) console.log("[Realtime] subscribe callback fired. subStatus=", subStatus, "err=", err);
        if (REALTIME_DEBUG) console.log(`[Realtime:${table}] channel status → ${subStatus}`);
        if (subStatus === "SUBSCRIBED") setStatus("live");
        else if (subStatus === "CHANNEL_ERROR") setStatus("error");
        else if (subStatus === "TIMED_OUT") setStatus("error");
        else if (subStatus === "CLOSED") setStatus("disconnected");
      });

    channelRef.current = channel;

    return () => {
      for (const timerId of highlightTimersRef.current.values()) {
        window.clearTimeout(timerId);
      }
      highlightTimersRef.current.clear();
      if (channelRef.current) {
        supabase.removeChannel(channelRef.current);
        channelRef.current = null;
      }
    };
  }, [enabled, orgId, table, maxItems, highlightMs]);

  return { rows, status, setRows, newCount, acknowledgeNew };
}