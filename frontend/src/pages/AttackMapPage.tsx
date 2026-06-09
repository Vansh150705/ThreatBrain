import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import { Loader2, AlertCircle, Globe, ShieldAlert, MapPin } from "lucide-react";

import { api, type GeoThreatPoint, type GeoThreatResponse } from "@/lib/api";
import { ApiError } from "@/lib/api";
import { useRealtimeThreats } from "@/hooks/useRealtimeThreats";

// ─── Constants ───────────────────────────────────────────────────────────────

const SEVERITY_HEX: Record<string, string> = {
  critical: "#dc2626",
  high:     "#ea580c",
  medium:   "#d97706",
  low:      "#16a34a",
  info:     "#2563eb",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

const SEVERITY_TONE: Record<string, string> = {
  critical: "text-severity-critical border-severity-critical/30 bg-severity-critical/8",
  high:     "text-severity-high border-severity-high/30 bg-severity-high/8",
  medium:   "text-severity-medium border-severity-medium/30 bg-severity-medium/8",
  low:      "text-severity-low border-severity-low/30 bg-severity-low/8",
  info:     "text-severity-info border-severity-info/30 bg-severity-info/8",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function dotRadius(count: number): number {
  return Math.min(24, Math.max(8, 8 + Math.sqrt(count) * 4));
}

function timeAgo(iso: string): string {
  const diffMins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const h = Math.floor(diffMins / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function LiveIndicator({
  status,
}: {
  status: "connecting" | "live" | "disconnected" | "error";
}) {
  const config = {
    live:         { dotClass: "bg-severity-low",         label: "Live",       pulse: true  },
    connecting:   { dotClass: "bg-muted-foreground/40",  label: "Connecting", pulse: false },
    disconnected: { dotClass: "bg-muted-foreground/30",  label: "Offline",    pulse: false },
    error:        { dotClass: "bg-severity-critical",    label: "Error",      pulse: false },
  }[status];

  return (
    <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
      <span className="relative flex items-center justify-center">
        <span className={`w-1.5 h-1.5 rounded-full ${config.dotClass}`} />
        {config.pulse && (
          <span className={`absolute w-1.5 h-1.5 rounded-full ${config.dotClass} animate-ping opacity-75`} />
        )}
      </span>
      <span>{config.label}</span>
    </div>
  );
}

// Map dot with pulsing SVG path class via ref
function PulsingMarker({
  point,
  isNew,
}: {
  point: GeoThreatPoint;
  isNew: boolean;
}) {
  const markerRef = useRef<L.CircleMarker | null>(null);
  const color = SEVERITY_HEX[point.severity] ?? SEVERITY_HEX.info;
  const radius = dotRadius(point.threat_count);

  // Apply/remove CSS class on the underlying SVG path element
  useEffect(() => {
    const el = markerRef.current?.getElement();
    if (!el) return;
    const cls = isNew ? "attack-pulse-new" : "attack-pulse";
    const remove = isNew ? "attack-pulse" : "attack-pulse-new";
    el.classList.remove(remove);
    el.classList.add(cls);
  }, [isNew]);

  return (
    <CircleMarker
      ref={markerRef}
      center={[point.latitude, point.longitude]}
      radius={radius}
      pathOptions={{
        fillColor: color,
        fillOpacity: 0.6,
        color,
        weight: 2,
        opacity: 0.9,
      }}
    >
      <Popup>
        <div className="min-w-[200px] max-w-[280px]">
          <div className="font-semibold text-[13px] mb-1">
            {point.country_name}
            {point.city ? ` — ${point.city}` : ""}
          </div>
          <div className="text-[11px] text-muted-foreground mb-2">
            {point.threat_count} threat{point.threat_count !== 1 ? "s" : ""} from{" "}
            {point.source_ips.length} source IP{point.source_ips.length !== 1 ? "s" : ""}
          </div>
          <div className="space-y-1.5">
            {point.recent_threats.slice(0, 3).map((t) => (
              <div key={t.short_id} className="flex items-start gap-1.5">
                <span
                  className={`inline-flex items-center px-1 py-0.5 rounded text-[9px] uppercase tracking-[0.05em] font-mono font-semibold border flex-shrink-0 mt-[1px] ${
                    SEVERITY_TONE[t.severity] ?? SEVERITY_TONE.info
                  }`}
                >
                  {t.severity}
                </span>
                <Link
                  to={`/threats/${t.short_id}`}
                  className="text-[11px] text-foreground hover:underline leading-tight"
                >
                  {t.title.length > 60 ? t.title.slice(0, 57) + "…" : t.title}
                  <span className="font-mono text-[9px] text-muted-foreground ml-1 block">
                    {t.short_id} · {timeAgo(t.detected_at)}
                  </span>
                </Link>
              </div>
            ))}
          </div>
        </div>
      </Popup>
    </CircleMarker>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function AttackMapPage() {
  const [geoData, setGeoData] = useState<GeoThreatResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Countries that have new arrivals (set → 3s timeout → removed)
  const [newCountries, setNewCountries] = useState<Set<string>>(new Set());
  // Banner for latest new arrival
  const [arrivalBanner, setArrivalBanner] = useState<string | null>(null);

  const { threats, status: liveStatus } = useRealtimeThreats({ enabled: true });
  const prevThreatIds = useRef<Set<string>>(new Set());

  // ── Initial fetch ──────────────────────────────────────────────────────────
  const fetchGeo = () =>
    api.threats
      .getGeoThreats()
      .then((data) => {
        setGeoData(data);
        setError(null);
      })
      .catch((err) => {
        if (err instanceof ApiError) setError(`${err.status} — ${err.message}`);
        else setError(String(err));
      })
      .finally(() => setLoading(false));

  useEffect(() => {
    fetchGeo();
  }, []);

  // ── Realtime arrivals ──────────────────────────────────────────────────────
  useEffect(() => {
    if (!geoData) return;

    const newArrivals = threats.filter(
      (t) => t._isNew && !prevThreatIds.current.has(t.id)
    );

    if (newArrivals.length === 0) return;

    // Mark all current threat IDs as seen
    threats.forEach((t) => prevThreatIds.current.add(t.id));

    let needsRefetch = false;
    const triggered = new Set<string>();

    for (const threat of newArrivals) {
      // Check if any of this threat's source IPs match a known country on the map
      const matched = geoData.items.filter((p) =>
        p.source_ips.some((ip) => (threat.source_ips ?? []).includes(ip))
      );

      if (matched.length > 0) {
        matched.forEach((p) => triggered.add(p.country));
      } else {
        needsRefetch = true;
      }
    }

    if (triggered.size > 0) {
      setNewCountries((prev) => {
        const next = new Set(prev);
        triggered.forEach((cc) => next.add(cc));
        return next;
      });
      // Show banner for first matched country
      const firstCountry = geoData.items.find((p) => triggered.has(p.country));
      if (firstCountry) {
        setArrivalBanner(`New attack from ${firstCountry.country_name}`);
        setTimeout(() => setArrivalBanner(null), 2000);
      }
      // Revert pulse after 3 seconds
      setTimeout(() => {
        setNewCountries((prev) => {
          const next = new Set(prev);
          triggered.forEach((cc) => next.delete(cc));
          return next;
        });
      }, 3000);
    }

    if (needsRefetch) {
      fetchGeo();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [threats]);

  // ── Derived stats ──────────────────────────────────────────────────────────
  const highestRiskCountry = geoData?.items.reduce<GeoThreatPoint | null>((best, p) => {
    if (!best) return p;
    return SEVERITY_ORDER[p.severity] > SEVERITY_ORDER[best.severity] ? p : best;
  }, null);

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <section className="flex items-start justify-between gap-6 flex-wrap">
        <div>
          <h1 className="text-[26px] tracking-[-0.025em] font-semibold text-foreground">
            Attack Map
          </h1>
          <p className="text-[13.5px] text-muted-foreground mt-1">
            Live geographic distribution of attack sources.
          </p>
        </div>
        <LiveIndicator status={liveStatus} />
      </section>

      {/* Stat strip */}
      <section>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            {
              label: "Active source countries",
              value: loading ? "—" : (geoData?.total_countries ?? 0).toString(),
              caption: "distinct nation-states",
              icon: Globe,
              iconBg: "bg-severity-info/10 text-severity-info",
            },
            {
              label: "Total active threats",
              value: loading ? "—" : (geoData?.total_threats ?? 0).toString(),
              caption: "open / investigating / contained",
              icon: ShieldAlert,
              iconBg: "bg-severity-high/10 text-severity-high",
            },
            {
              label: "Highest risk region",
              value: loading ? "—" : (highestRiskCountry?.country_name ?? "None"),
              caption: loading ? "" : highestRiskCountry ? `${highestRiskCountry.severity} · ${highestRiskCountry.threat_count} threats` : "no data",
              icon: MapPin,
              iconBg: "bg-severity-critical/10 text-severity-critical",
            },
          ].map((s) => {
            const Icon = s.icon;
            return (
              <div key={s.label} className="bg-card border border-border rounded-xl p-5">
                <div className="flex items-start justify-between mb-4">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${s.iconBg}`}>
                    <Icon className="w-4 h-4" strokeWidth={2} />
                  </div>
                </div>
                <div className="text-[12px] text-muted-foreground font-medium mb-1.5">{s.label}</div>
                <div className="text-[28px] leading-[1] tracking-[-0.025em] font-semibold text-foreground tabular truncate">
                  {s.value}
                </div>
                <div className="font-mono text-[11px] text-muted-foreground mt-3 tracking-tight">
                  {s.caption || "—"}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Map card */}
      <section>
        <div className="bg-card border border-border rounded-xl overflow-hidden relative">
          {/* Arrival banner */}
          <AnimatePresence>
            {arrivalBanner && (
              <motion.div
                key="banner"
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.2 }}
                className="absolute top-3 left-1/2 -translate-x-1/2 z-[1000] px-4 py-2 rounded-lg bg-severity-critical/90 text-white font-mono text-[11px] font-semibold uppercase tracking-[0.08em] shadow-lg pointer-events-none"
              >
                {arrivalBanner}
              </motion.div>
            )}
          </AnimatePresence>

          {loading && (
            <div className="flex items-center gap-2 text-muted-foreground text-[13px] p-8">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading geo data…
            </div>
          )}

          {error && (
            <div className="m-5 flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
              <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
              <div className="text-[13px] text-foreground">
                <div className="font-semibold">Could not load geo data</div>
                <div className="text-muted-foreground mt-0.5 font-mono text-[11px]">{error}</div>
              </div>
            </div>
          )}

          <MapContainer
            center={[20, 0]}
            zoom={2}
            scrollWheelZoom
            doubleClickZoom
            dragging
            style={{ height: "600px", width: "100%" }}
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
            />
            {!loading &&
              !error &&
              geoData?.items.map((point) => (
                <PulsingMarker
                  key={point.country}
                  point={point}
                  isNew={newCountries.has(point.country)}
                />
              ))}
          </MapContainer>
        </div>
      </section>

      {/* Legend */}
      <section>
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3">
            Severity legend
          </div>
          <div className="flex flex-wrap gap-4">
            {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
              <div key={sev} className="flex items-center gap-2">
                <span
                  className="w-3 h-3 rounded-full flex-shrink-0"
                  style={{ backgroundColor: SEVERITY_HEX[sev] }}
                />
                <span
                  className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] uppercase tracking-[0.06em] font-mono font-semibold border ${
                    SEVERITY_TONE[sev]
                  }`}
                >
                  {sev}
                </span>
              </div>
            ))}
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground ml-4 font-mono">
              <span>Dot size scales with threat count</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
