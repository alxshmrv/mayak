import {
  Activity, AlertTriangle, Bell, Bookmark, Camera, Check, ChevronDown,
  ChevronRight, CircleCheck, CircleHelp, Clock3, Eye, Gauge, History, Info,
  Download, Laptop, Lock, MapPin, Network, Printer, Radar, Radio, RefreshCw,
  Router, Search, Settings, ShieldCheck, Signal, SlidersHorizontal, Smartphone,
  Languages, Tablet, Tv, UserCheck, Wifi, X, type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import {
  getAppSnapshot, getHistory, listenAppEvent, openPrivacySettings,
  requestLocationPermission, requestNotificationPermission, runScan,
  saveSettings, setDeviceTrust,
} from "./api";
import crabImage from "./assets/mayak-crab.png";
import {
  I18nContext, detectLanguage, messages, resolveLanguage, useI18n, type LanguagePreference, type Messages,
} from "./i18n";
import type {
  AppSettings, AppSnapshot, Confidence, DeviceKind, Finding, HistoryEntry,
  ObservedDevice, PermissionState, ScanMode, ScanProgress, ScanReport, Severity,
  TrustState,
} from "./types";
import { useAppUpdater, type AppUpdateState } from "./useAppUpdater";

type View = "overview" | "devices" | "history" | "settings";
type MascotMood = "idle" | "peek" | "scuttle" | "scan" | "wave" | "concerned";

const severityMeta: Record<Severity, { className: string; icon: LucideIcon }> = {
  good: { className: "tone-good", icon: CircleCheck },
  info: { className: "tone-info", icon: Info },
  warning: { className: "tone-warning", icon: AlertTriangle },
  high: { className: "tone-danger", icon: AlertTriangle },
  critical: { className: "tone-critical", icon: AlertTriangle },
};

const deviceKindIcon: Record<DeviceKind, LucideIcon> = {
  router: Router,
  computer: Laptop,
  phone: Smartphone,
  tablet: Tablet,
  printer: Printer,
  media: Tv,
  smartHome: Radio,
  camera: Camera,
  possibleCamera: Eye,
  networkEquipment: Network,
  unknown: CircleHelp,
};

const trustIcon: Record<TrustState, LucideIcon> = {
  unknown: CircleHelp,
  mine: UserCheck,
  known: Bookmark,
  ignored: Eye,
};

function isUnreviewedNew(device: ObservedDevice) {
  return device.isNew && device.trustState === "unknown" && device.kind !== "router";
}

function formatDate(t: Messages, value: string, withDate = false) {
  return new Intl.DateTimeFormat(t.locale, {
    day: withDate ? "numeric" : undefined,
    month: withDate ? "short" : undefined,
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function normalizeSecurity(t: Messages, value: string) {
  const labels: Record<string, string> = {
    open: t.security.open, wep: "WEP", "wpa-personal": "WPA Personal",
    "wpa2-personal": "WPA2 Personal", "wpa3-personal": "WPA3 Personal",
    "wpa2-wpa3-transition": "WPA2 / WPA3", "wpa-enterprise": "WPA Enterprise",
    "wpa2-enterprise": "WPA2 Enterprise", "wpa3-enterprise": "WPA3 Enterprise",
    owe: "Enhanced Open (OWE)", unknown: t.security.unknown,
  };
  return labels[value] ?? value.replaceAll("-", " ").toUpperCase();
}

function radioValue(t: Messages, value: string) {
  return value === "unknown" ? t.unknownValue : t.radioUnits(value);
}

function DeviceIcon({ kind, size = "regular" }: {
  kind: DeviceKind; size?: "small" | "regular" | "large";
}) {
  const Icon = deviceKindIcon[kind];
  return <span className={`device-icon device-icon--${kind} device-icon--${size}`}><Icon aria-hidden="true" /></span>;
}

function StatusPill({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  const t = useI18n();
  const meta = severityMeta[severity];
  const Icon = meta.icon;
  return (
    <span className={`status-pill ${meta.className} ${compact ? "is-compact" : ""}`}>
      <Icon aria-hidden="true" />{t.severity[severity]}
    </span>
  );
}

function Mascot({ mood, message }: { mood: MascotMood; message: string }) {
  return (
    <div className={`mascot mascot--${mood}`} aria-live="polite">
      <div className="mascot__message">{message}</div>
      <div className="mascot__stage" aria-hidden="true">
        <span className="mascot__ping mascot__ping--one" />
        <span className="mascot__ping mascot__ping--two" />
        <img src={crabImage} alt="" className="mascot__image" />
        <span className="mascot__shadow" />
      </div>
    </div>
  );
}

type RadarNodeStyle = CSSProperties & {
  "--node-x": string;
  "--node-y": string;
};

const confidenceRadius: Record<Confidence, number> = {
  high: 30,
  medium: 39,
  low: 44,
};

function Topology({ report, isScanning, onSelectDevice }: {
  report: ScanReport; isScanning: boolean; onSelectDevice: (device: ObservedDevice) => void;
}) {
  const t = useI18n();
  const visibleDevices = report.devices.slice(0, 8);
  const nodes = visibleDevices.map((device, index) => {
    const angle = -90 + (360 / Math.max(visibleDevices.length, 1)) * index;
    const radians = angle * Math.PI / 180;
    const radius = confidenceRadius[device.typeConfidence];
    const x = 50 + Math.cos(radians) * radius;
    const y = 50 + Math.sin(radians) * radius;
    return {
      device,
      x,
      y,
      style: {
        "--node-x": `${x}%`,
        "--node-y": `${y}%`,
      } as RadarNodeStyle,
    };
  });

  return (
    <div className={`topology ${isScanning ? "is-scanning" : ""}`} aria-label={t.radar.label}>
      <div className="topology__caption"><strong>{t.radar.title}</strong><span>{t.radar.subtitle}</span></div>
      <div className="topology__plot">
        <div className="topology__rings" aria-hidden="true"><span /><span /><span /></div>
        <svg className="topology__links" viewBox="0 0 100 100" aria-hidden="true">
          {nodes.map(({ device, x, y }) => (
            <line x1="50" y1="50" x2={x} y2={y} key={device.identityKey} />
          ))}
        </svg>
        <div className="topology__pulses" aria-hidden="true"><span /><span /><span /></div>
        <div className="topology__center"><Wifi aria-hidden="true" /><span>{report.network.ssid ?? "Wi-Fi"}</span></div>
        {nodes.map(({ device, style }) => {
        const Icon = deviceKindIcon[device.kind];
        return (
          <button
            type="button"
            className={`topology__device ${isUnreviewedNew(device) ? "is-new" : ""}`}
            key={device.identityKey}
            style={style}
            data-confidence={device.typeConfidence}
            onClick={() => onSelectDevice(device)}
            aria-label={`${device.displayName}, ${t.deviceKind[device.kind]}`}
          >
            <Icon aria-hidden="true" />
            <span className="topology__device-label">{device.displayName}</span>
          </button>
        );
      })}
      </div>
      <div className="topology__legend" aria-hidden="true">
        <span><i data-confidence="high" />{t.radar.high}</span>
        <span><i data-confidence="medium" />{t.radar.medium}</span>
        <span><i data-confidence="low" />{t.radar.low}</span>
      </div>
      {report.devices.length > 8 && <div className="topology__more">{t.radar.more(report.devices.length - 8)}</div>}
    </div>
  );
}

function FindingRow({ finding, defaultOpen = false }: { finding: Finding; defaultOpen?: boolean }) {
  const t = useI18n();
  const [open, setOpen] = useState(defaultOpen);
  const meta = severityMeta[finding.severity];
  const Icon = meta.icon;
  return (
    <article className={`finding ${meta.className}`}>
      <button type="button" className="finding__summary" onClick={() => setOpen((value) => !value)} aria-expanded={open}>
        <span className="finding__icon"><Icon aria-hidden="true" /></span>
        <span className="finding__copy"><strong>{finding.title}</strong><span>{finding.description}</span></span>
        <ChevronDown className={open ? "is-rotated" : ""} aria-hidden="true" />
      </button>
      {open && (
        <div className="finding__details">
          {finding.recommendation && (
            <p className="finding__recommendation"><ShieldCheck aria-hidden="true" /><span>{finding.recommendation}</span></p>
          )}
          {finding.evidence.length > 0 && (
            <div><span className="eyebrow">{t.finding.evidence}</span><ul>
              {finding.evidence.map((item) => <li key={item}>{item}</li>)}
            </ul></div>
          )}
        </div>
      )}
    </article>
  );
}

function NetworkFacts({ report }: { report: ScanReport }) {
  const t = useI18n();
  const { network, coverage } = report;
  const f = t.facts;
  const facts = [
    [f.interface, network.interfaceName ?? "—"], ["BSSID", network.bssid ?? f.bssidHidden],
    [f.ipv4, network.ipv4 ?? "—"], [f.subnet, network.subnet ?? "—"],
    [f.gateway, network.router ?? "—"], [f.dns, network.dnsServers.join(", ") || "—"],
    [f.band, network.channel ? radioValue(t, network.channel.band) : "—"],
    [f.channel, network.channel ? `${network.channel.number} · ${radioValue(t, network.channel.width)}` : "—"],
    [f.mode, network.phyMode ?? "—"],
    [f.phyRate, network.transmitRateMbps ? `${network.transmitRateMbps} ${f.mbps}` : "—"],
    [f.rssiNoise, network.rssi ? `${network.rssi} / ${network.noise ?? "—"} dBm` : "—"],
    [f.country, network.countryCode ?? "—"], [f.ipv6, network.ipv6.join(", ") || "—"],
    [f.proxy, network.proxyEnabled ? f.proxyOn : f.notDetected],
    [f.vpn, network.vpnActive ? f.vpnOn : f.notDetected],
  ];
  return (
    <details className="technical-panel">
      <summary><span><SlidersHorizontal aria-hidden="true" />{f.title}</span><ChevronDown aria-hidden="true" /></summary>
      <div className="technical-panel__body">
        <dl className="facts">{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
        <div className="coverage-detail">
          <div><span className="eyebrow">{f.methods}</span><p>{coverage.methods.join(" · ")}</p></div>
          <div><span className="eyebrow">{f.coverage}</span><p>
            {f.coverageSummary(coverage.targetCount, coverage.responsiveCount)} · ARP {coverage.arpCount}
            {" "}· Bonjour {coverage.mdnsCount} · SSDP {coverage.ssdpCount} · ONVIF {coverage.onvifCount}
          </p></div>
          {coverage.notes.map((note) => <p className="coverage-note" key={note}><Info aria-hidden="true" />{note}</p>)}
        </div>
      </div>
    </details>
  );
}

function Overview({ report, isScanning, onSelectDevice, onShowDevices }: {
  report: ScanReport; isScanning: boolean; onSelectDevice: (device: ObservedDevice) => void; onShowDevices: () => void;
}) {
  const t = useI18n();
  const o = t.overview;
  const risk = severityMeta[report.assessment.risk];
  const RiskIcon = risk.icon;
  const newDevices = report.devices.filter(isUnreviewedNew).length;
  const concerning = report.devices.filter((device) => device.kind === "camera" || device.kind === "possibleCamera").length;
  return (
    <div className="view-stack overview">
      <section className="network-hero">
        <div className="network-hero__copy">
          <span className="eyebrow">{o.eyebrow}</span>
          <div className="network-title"><h1>{report.network.ssid ?? o.unnamedNetwork}</h1><StatusPill severity={report.assessment.risk} /></div>
          <div className={`verdict ${risk.className}`}>
            <span className="verdict__icon"><RiskIcon aria-hidden="true" /></span>
            <div><h2>{report.assessment.summary}</h2><p>{o.verdictNote}</p></div>
          </div>
          <div className="network-signal">
            <Signal aria-hidden="true" /><div><strong>{report.network.signalQuality ?? "—"}%</strong><span>{o.signal}</span></div>
            <span className="network-signal__divider" />
            <Lock aria-hidden="true" /><div><strong>{normalizeSecurity(t, report.network.security)}</strong><span>{o.wifiSecurity}</span></div>
          </div>
        </div>
        <Topology report={report} isScanning={isScanning} onSelectDevice={onSelectDevice} />
      </section>
      <section className="metric-rail" aria-label={o.summaryLabel}>
        <button type="button" onClick={onShowDevices}><span className="metric-rail__icon metric-rail__icon--accent"><Radar aria-hidden="true" /></span><span><strong>{report.devices.length}</strong><small>{o.devicesVisible(report.devices.length)}</small></span><ChevronRight aria-hidden="true" /></button>
        <button type="button" onClick={onShowDevices}><span className="metric-rail__icon metric-rail__icon--new"><Activity aria-hidden="true" /></span><span><strong>{newDevices}</strong><small>{o.unreviewedNew}</small></span><ChevronRight aria-hidden="true" /></button>
        <div><span className="metric-rail__icon"><Eye aria-hidden="true" /></span><span><strong>{t.visibility[report.assessment.visibility].label}</strong><small>{o.networkVisibility}</small></span></div>
        <div className={concerning > 0 ? "is-concerning" : ""}><span className="metric-rail__icon"><Camera aria-hidden="true" /></span><span><strong>{concerning || o.none}</strong><small>{concerning ? o.needsReview : o.cameraSigns}</small></span></div>
      </section>
      <section className="content-section">
        <div className="section-heading"><div><span className="eyebrow">{o.resultEyebrow}</span><h2>{o.resultTitle}</h2></div><span className="section-heading__meta">{o.confidence(t.confidence[report.assessment.confidence])}</span></div>
        <div className="findings">{report.assessment.findings.map((finding, index) => (
          <FindingRow finding={finding} defaultOpen={index === 0 && finding.severity !== "good"} key={finding.id} />
        ))}</div>
      </section>
      <NetworkFacts report={report} />
      <p className="scan-footnote">{o.footnote(formatDate(t, report.completedAt), t.duration(report.durationMs), report.mode === "deep")}</p>
    </div>
  );
}

function DeviceDetails({ device, onClose, onTrustChange }: {
  device: ObservedDevice; onClose: () => void; onTrustChange: (trust: TrustState) => void;
}) {
  const t = useI18n();
  const d = t.device;
  return (
    <aside className="device-drawer" aria-label={d.detailsLabel(device.displayName)}>
      <div className="device-drawer__header">
        <DeviceIcon kind={device.kind} size="large" />
        <div><span className="eyebrow">{t.deviceKind[device.kind]}</span><h2>{device.displayName}</h2></div>
        <button type="button" className="icon-button" onClick={onClose} aria-label={t.close}><X aria-hidden="true" /></button>
      </div>
      {(device.kind === "camera" || device.kind === "possibleCamera") && (
        <div className="device-alert"><AlertTriangle aria-hidden="true" /><div>
          <strong>{device.kind === "camera" ? d.cameraConfirmed : d.cameraPossible}</strong>
          <p>{d.cameraNote}</p>
        </div></div>
      )}
      <div className="trust-selector"><span className="eyebrow">{d.trustTitle}</span><div>
        {(["unknown", "mine", "known", "ignored"] as TrustState[]).map((trust) => {
          const Icon = trustIcon[trust];
          return <button type="button" className={device.trustState === trust ? "is-selected" : ""} key={trust} onClick={() => onTrustChange(trust)}>
            <Icon aria-hidden="true" />{t.trust[trust]}{device.trustState === trust && <Check aria-hidden="true" />}
          </button>;
        })}
      </div></div>
      <dl className="device-facts">
        <div><dt>{d.ipAddresses}</dt><dd>{device.ipAddresses.join(", ")}</dd></div>
        <div><dt>{d.mac}</dt><dd>{device.macAddress ?? d.macHidden}</dd></div>
        <div><dt>{d.vendor}</dt><dd>{device.vendor ?? d.vendorUnknown}</dd></div>
        <div><dt>{d.names}</dt><dd>{device.hostnames.join(", ") || d.namesNone}</dd></div>
        <div><dt>{d.openPorts}</dt><dd>{device.openPorts.join(", ") || d.portsNone}</dd></div>
        <div><dt>{d.firstSeen}</dt><dd>{formatDate(t, device.firstSeen, true)}</dd></div>
        <div><dt>{d.lastSeen}</dt><dd>{formatDate(t, device.lastSeen, true)}</dd></div>
        <div><dt>{d.typeConfidence}</dt><dd>{t.confidence[device.typeConfidence]}</dd></div>
      </dl>
      {device.services.length > 0 && <section className="device-services"><span className="eyebrow">{d.services}</span>
        {device.services.map((service, index) => <div key={`${service.protocol}-${service.name}-${index}`}><Radio aria-hidden="true" /><span>
          <strong>{service.name}</strong><small>{service.protocol.toUpperCase()}{service.serviceType ? ` · ${service.serviceType}` : ""}{service.port ? ` · ${d.port(service.port)}` : ""}</small>
        </span></div>)}
      </section>}
      <section className="device-evidence"><span className="eyebrow">{d.whyVisible}</span><ul>
        {device.evidence.map((item) => <li key={item}>{item}</li>)}
      </ul></section>
    </aside>
  );
}

function DevicesView({ report, selectedDevice, onSelectedDevice, onTrustChange }: {
  report: ScanReport; selectedDevice?: ObservedDevice; onSelectedDevice: (device?: ObservedDevice) => void;
  onTrustChange: (device: ObservedDevice, trust: TrustState) => void;
}) {
  const t = useI18n();
  const v = t.devices;
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "new" | "attention" | "known">("all");
  const devices = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return report.devices.filter((device) => {
      const matchesQuery = !needle || [device.displayName, device.vendor, device.macAddress, ...device.ipAddresses, ...device.hostnames]
        .filter(Boolean).some((value) => value?.toLowerCase().includes(needle));
      const matchesFilter = filter === "all" || (filter === "new" && isUnreviewedNew(device)) ||
        (filter === "attention" && (device.findings.length > 0 || device.kind === "camera" || device.kind === "possibleCamera")) ||
        (filter === "known" && (device.trustState === "mine" || device.trustState === "known"));
      return matchesQuery && matchesFilter;
    });
  }, [filter, query, report.devices]);
  return (
    <div className={`devices-layout ${selectedDevice ? "has-drawer" : ""}`}>
      <div className="devices-main">
        <div className="page-heading"><div><span className="eyebrow">{v.eyebrow}</span><h1>{v.title}</h1><p>{v.description}</p></div><span className="count-badge">{report.devices.length}</span></div>
        <div className="device-tools">
          <label className="search-field"><Search aria-hidden="true" /><span className="sr-only">{v.search}</span>
            <input type="search" placeholder={v.searchPlaceholder} value={query} onChange={(event) => setQuery(event.target.value)} />
            {query && <button type="button" onClick={() => setQuery("")} aria-label={v.clearSearch}><X aria-hidden="true" /></button>}
          </label>
          <div className="filter-tabs" aria-label={v.filterLabel}>
            {(["all", "new", "attention", "known"] as const).map((value) => (
              <button type="button" className={filter === value ? "is-active" : ""} onClick={() => setFilter(value)} key={value}>{v.filters[value]}</button>
            ))}
          </div>
        </div>
        <div className="device-list">
          <div className="device-list__header" aria-hidden="true">{v.columns.map((column) => <span key={column}>{column}</span>)}</div>
          {devices.map((device) => {
            const isConcern = device.kind === "camera" || device.kind === "possibleCamera" ||
              device.findings.some((item) => ["warning", "high", "critical"].includes(item.severity));
            return <button type="button" className={`device-row ${selectedDevice?.identityKey === device.identityKey ? "is-selected" : ""}`} key={device.identityKey} onClick={() => onSelectedDevice(device)}>
              <span className="device-row__name"><DeviceIcon kind={device.kind} /><span><strong>{device.displayName}</strong><small>{t.deviceKind[device.kind]}{device.vendor ? ` · ${device.vendor}` : ""}</small></span></span>
              <span className="device-row__address"><span><strong>{device.ipAddresses[0] ?? "—"}</strong><small>{device.macAddress ?? v.macHidden}</small></span></span>
              <span className="device-row__evidence"><span><strong>{device.openPorts.length ? v.ports(device.openPorts.slice(0, 4).join(", ")) : v.noPorts}</strong><small>{device.services.length ? v.services(device.services.length) : v.typeConfidence(t.confidence[device.typeConfidence])}</small></span></span>
              <span className="device-row__status">
                {isConcern ? <span className="mini-tag mini-tag--warning"><AlertTriangle aria-hidden="true" />{v.review}</span>
                  : isUnreviewedNew(device) ? <span className="mini-tag mini-tag--new">{v.new}</span>
                    : device.trustState !== "unknown" ? <span className="mini-tag">{t.trust[device.trustState]}</span>
                      : <span className="mini-tag mini-tag--quiet">{v.observed}</span>}
                <ChevronRight aria-hidden="true" />
              </span>
            </button>;
          })}
          {devices.length === 0 && <div className="empty-state"><Search aria-hidden="true" /><h2>{v.emptyTitle}</h2><p>{v.emptyDescription}</p></div>}
        </div>
      </div>
      {selectedDevice && <DeviceDetails device={selectedDevice} onClose={() => onSelectedDevice(undefined)} onTrustChange={(trust) => onTrustChange(selectedDevice, trust)} />}
    </div>
  );
}

function HistoryView({ entries, activeReport }: { entries: HistoryEntry[]; activeReport?: ScanReport }) {
  const t = useI18n();
  const h = t.history;
  return (
    <div className="view-stack">
      <div className="page-heading"><div><span className="eyebrow">{h.eyebrow}</span><h1>{h.title}</h1><p>{h.description}</p></div></div>
      <section className="history-timeline">
        {entries.map((entry) => {
          const meta = severityMeta[entry.risk]; const Icon = meta.icon; const isCurrent = entry.id === activeReport?.id;
          return <article className={isCurrent ? "is-current" : ""} key={entry.id}>
            <div className={`history-timeline__marker ${meta.className}`}><Icon aria-hidden="true" /></div>
            <div className="history-timeline__content"><div>
              <span className="history-timeline__date">{formatDate(t, entry.completedAt, true)}{isCurrent && <em>{h.current}</em>}</span>
              <h2>{entry.ssid ?? t.overview.unnamedNetwork}</h2><p>{normalizeSecurity(t, entry.security)}</p>
            </div><div className="history-timeline__stats">
              <span><strong>{entry.deviceCount}</strong> {h.devices(entry.deviceCount)}</span><span><strong>{entry.newDeviceCount}</strong> {h.newDevices(entry.newDeviceCount)}</span>
              <span><strong>{t.visibility[entry.visibility].label}</strong> {h.visibility}</span><StatusPill severity={entry.risk} compact />
            </div></div>
          </article>;
        })}
        {entries.length === 0 && <div className="empty-state"><History aria-hidden="true" /><h2>{h.emptyTitle}</h2><p>{h.emptyDescription}</p></div>}
      </section>
      <div className="privacy-note"><ShieldCheck aria-hidden="true" /><div><strong>{h.privacyTitle}</strong><p>{h.privacyDescription}</p></div></div>
    </div>
  );
}

function UpdateSettings({ update, onCheck, onInstall, onOpen }: {
  update: AppUpdateState;
  onCheck: () => void;
  onInstall: () => void;
  onOpen: () => void;
}) {
  const t = useI18n();
  const u = t.update;
  const isBusy = update.phase === "checking" ||
    update.phase === "downloading" ||
    update.phase === "installing" ||
    update.phase === "restarting";
  const status = update.phase === "checking" ? u.checking
    : update.phase === "available" ? u.available(update.available?.version ?? "")
      : update.phase === "downloading" ? u.downloaded(t.bytes(update.downloadedBytes))
        : update.phase === "installing" ? u.installing
          : update.phase === "restarting" ? u.restarting
            : update.phase === "current" ? u.current
              : update.phase === "failed" ? u.failed
                : u.schedule;
  const action = update.available
    ? update.phase === "available" || update.phase === "failed"
      ? <button type="button" className="secondary-button" onClick={update.phase === "failed" ? onInstall : onOpen}>
          {update.phase === "failed" ? u.retryInstall : u.view}
        </button>
      : <button type="button" className="secondary-button" disabled>{u.inProgress}</button>
    : <button type="button" className="secondary-button" disabled={isBusy} onClick={onCheck}>
        <RefreshCw className={update.phase === "checking" ? "is-spinning" : ""} aria-hidden="true" />
        {update.phase === "checking" ? u.checkingShort : u.check}
      </button>;
  return (
    <section className="settings-group">
      <div className="settings-group__heading"><Download aria-hidden="true" /><div><h2>{u.title}</h2><p>{u.description}</p></div></div>
      <div className="permission-row"><span><strong>{u.version}</strong><small>{update.installedVersion ?? u.detectingVersion}</small></span>{action}</div>
      <div className={`update-status update-status--${update.phase}`}>
        <ShieldCheck aria-hidden="true" />
        <span><strong>{status}</strong>{update.lastCheckedAt && <small>{u.lastChecked(formatDate(t, update.lastCheckedAt, true))}</small>}</span>
      </div>
    </section>
  );
}

function SettingsView({ settings, permissions, locationRequestAttempted, update, onSettingsChange, onRequestLocation, onOpenPrivacySettings, onCheckUpdates, onInstallUpdate, onOpenUpdate }: {
  settings: AppSettings; permissions: AppSnapshot["permissions"]; locationRequestAttempted: boolean;
  update: AppUpdateState;
  onSettingsChange: (settings: AppSettings) => void; onRequestLocation: () => void;
  onOpenPrivacySettings: (section: "location" | "localNetwork") => void;
  onCheckUpdates: () => void; onInstallUpdate: () => void; onOpenUpdate: () => void;
}) {
  const t = useI18n();
  const g = t.settings;
  const patch = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => onSettingsChange({ ...settings, [key]: value });
  return (
    <div className="view-stack settings-view">
      <div className="page-heading"><div><span className="eyebrow">{g.eyebrow}</span><h1>{g.title}</h1><p>{g.description}</p></div></div>
      <section className="settings-group">
        <div className="settings-group__heading"><Radar aria-hidden="true" /><div><h2>{g.monitoringTitle}</h2><p>{g.monitoringDescription}</p></div></div>
        <label className="setting-row"><span><strong>{g.background}</strong><small>{g.backgroundHint}</small></span>
          <input type="checkbox" className="switch" checked={settings.backgroundMonitoring} onChange={(event) => patch("backgroundMonitoring", event.target.checked)} /></label>
        <label className="setting-row"><span><strong>{g.interval}</strong><small>{g.intervalHint}</small></span>
          <select value={settings.monitoringIntervalSeconds} disabled={!settings.backgroundMonitoring} onChange={(event) => patch("monitoringIntervalSeconds", Number(event.target.value))}>
            {[60, 300, 900, 1800].map((seconds) => <option value={seconds} key={seconds}>{g.intervals[seconds]}</option>)}
          </select></label>
        <label className="setting-row"><span><strong>{g.defaultMode}</strong><small>{g.defaultModeHint}</small></span>
          <select value={settings.defaultScanMode} onChange={(event) => patch("defaultScanMode", event.target.value as ScanMode)}>
            <option value="safe">{g.modeSafe}</option><option value="deep">{g.modeDeep}</option>
          </select></label>
      </section>
      <section className="settings-group">
        <div className="settings-group__heading"><Bell aria-hidden="true" /><div><h2>{g.alertsTitle}</h2><p>{g.alertsDescription}</p></div></div>
        <label className="setting-row"><span><strong>{g.newDevice}</strong><small>{g.newDeviceHint}</small></span>
          <input type="checkbox" className="switch" checked={settings.notifyNewDevices} onChange={(event) => patch("notifyNewDevices", event.target.checked)} /></label>
        <label className="setting-row"><span><strong>{g.networkChanged}</strong><small>{g.networkChangedHint}</small></span>
          <input type="checkbox" className="switch" checked={settings.notifyNetworkChanges} onChange={(event) => patch("notifyNetworkChanges", event.target.checked)} /></label>
      </section>
      <section className="settings-group">
        <div className="settings-group__heading"><Languages aria-hidden="true" /><div><h2>{g.languageTitle}</h2><p>{g.languageDescription}</p></div></div>
        <label className="setting-row"><span><strong>{g.language}</strong><small>{g.languageHint}</small></span>
          <select value={settings.language} onChange={(event) => patch("language", event.target.value as LanguagePreference)}>
            <option value="system">{g.languageSystem}</option><option value="ru" lang="ru">Русский</option><option value="en" lang="en">English</option>
          </select></label>
      </section>
      <UpdateSettings update={update} onCheck={onCheckUpdates} onInstall={onInstallUpdate} onOpen={onOpenUpdate} />
      <section className="settings-group">
        <div className="settings-group__heading"><MapPin aria-hidden="true" /><div><h2>{g.accessTitle}</h2><p>{g.accessDescription}</p></div></div>
        <div className="permission-row"><span><strong>{g.location}</strong><small>{t.permission[permissions.location]}</small></span>
          {permissions.location === "notDetermined" && !locationRequestAttempted ? <button type="button" className="secondary-button" onClick={onRequestLocation}>{g.allow}</button>
            : permissions.location !== "allowed" ? <button type="button" className="secondary-button" onClick={() => onOpenPrivacySettings("location")}>{g.openSettings}</button>
              : <span className="permission-ok"><Check aria-hidden="true" /> {g.allowed}</span>}</div>
        <div className="permission-row"><span><strong>{g.localNetwork}</strong><small>{t.permission[permissions.localNetwork]}</small></span>
          {permissions.localNetwork !== "allowed" ? <button type="button" className="secondary-button" onClick={() => onOpenPrivacySettings("localNetwork")}>{g.openSettings}</button>
            : <span className="permission-ok"><Check aria-hidden="true" /> {g.allowed}</span>}</div>
      </section>
    </div>
  );
}

function UpdateDialog({ update, onInstall, onClose }: {
  update: AppUpdateState;
  onInstall: () => void;
  onClose: () => void;
}) {
  const t = useI18n();
  const u = t.update;
  const available = update.available;
  if (!available || !update.dialogOpen) return null;

  const isBusy = update.phase === "downloading" ||
    update.phase === "installing" ||
    update.phase === "restarting";
  const percentage = update.totalBytes && update.totalBytes > 0
    ? Math.min(100, Math.round(update.downloadedBytes / update.totalBytes * 100))
    : undefined;
  const progressLabel = update.phase === "downloading"
    ? u.downloading(percentage)
    : update.phase === "installing" ? u.installingSigned
      : update.phase === "restarting" ? u.restarting
        : undefined;

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={isBusy ? undefined : onClose}>
      <section className="modal update-modal" role="dialog" aria-modal="true" aria-labelledby="update-title" onMouseDown={(event) => event.stopPropagation()}>
        {!isBusy && <button type="button" className="icon-button modal__close" onClick={onClose} aria-label={t.close}><X aria-hidden="true" /></button>}
        <span className="modal__icon"><Download aria-hidden="true" /></span>
        <span className="eyebrow">{u.dialogEyebrow}</span>
        <h2 id="update-title">{u.dialogTitle(available.version)}</h2>
        <p>{u.dialogBody(available.currentVersion)}</p>
        {available.notes && <div className="update-notes"><span className="eyebrow">{u.notes}</span><p>{available.notes}</p></div>}
        <div className="modal__facts">
          <span><ShieldCheck aria-hidden="true" /> {u.factSigned}</span>
          <span><Check aria-hidden="true" /> {u.factHttps}</span>
          <span><RefreshCw aria-hidden="true" /> {u.factRestart}</span>
        </div>
        {progressLabel && <div className="update-progress" aria-live="polite">
          <div><span>{progressLabel}</span>{update.totalBytes && <small>{u.progress(t.bytes(update.downloadedBytes), t.bytes(update.totalBytes))}</small>}</div>
          <progress value={percentage} max={100} />
        </div>}
        {update.error && <p className="update-error" role="alert">{u.failed}</p>}
        <div className="modal__actions">
          {!isBusy && <button type="button" className="secondary-button" onClick={onClose}>{u.later}</button>}
          <button type="button" className="primary-button" disabled={isBusy} onClick={onInstall}>
            <Download aria-hidden="true" />{isBusy ? u.updating : update.phase === "failed" ? u.retry : u.installAndRestart}
          </button>
        </div>
      </section>
    </div>
  );
}

function LocationNotice({ state, requestAttempted, onRequestLocation, onOpenSettings }: {
  state: PermissionState; requestAttempted: boolean; onRequestLocation: () => void; onOpenSettings: () => void;
}) {
  const t = useI18n();
  const n = t.location;
  const canRequest = state === "notDetermined" && !requestAttempted;
  return (
    <aside className="permission-notice" aria-label={n.label}>
      <span className="permission-notice__icon"><MapPin aria-hidden="true" /></span>
      <div><strong>{requestAttempted ? n.requested : n.hidden}</strong><p>
        {requestAttempted ? n.requestedHint : n.hiddenHint}
      </p></div>
      <button type="button" className="secondary-button" onClick={canRequest ? onRequestLocation : onOpenSettings}>
        {canRequest ? n.show : t.settings.openSettings}
      </button>
    </aside>
  );
}

function DisconnectedState({ onRetry }: { onRetry: () => void }) {
  const t = useI18n();
  const n = t.disconnected;
  return (
    <div className="permission-gate">
      <div className="permission-gate__visual permission-gate__visual--quiet"><Wifi /></div>
      <span className="eyebrow">{n.eyebrow}</span><h1>{n.title}</h1>
      <p>{n.description}</p>
      <button type="button" className="primary-button" onClick={onRetry}><RefreshCw aria-hidden="true" />{n.retry}</button>
    </div>
  );
}

export default function App() {
  const [snapshot, setSnapshot] = useState<AppSnapshot>();
  const [historyEntries, setHistoryEntries] = useState<HistoryEntry[]>([]);
  const [view, setView] = useState<View>("overview");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress>();
  const [selectedDevice, setSelectedDevice] = useState<ObservedDevice>();
  const [deepScanDialog, setDeepScanDialog] = useState(false);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [saved, setSaved] = useState(false);
  const [locationRequestAttempted, setLocationRequestAttempted] = useState(false);
  const [mascotMood, setMascotMood] = useState<MascotMood>("idle");
  const updater = useAppUpdater();
  const language = resolveLanguage(snapshot?.settings.language, snapshot?.systemLanguage ?? detectLanguage());
  const t = messages[language];

  useEffect(() => {
    document.documentElement.lang = language;
    document.title = t.appName;
  }, [language, t.appName]);

  const load = useCallback(async () => {
    try {
      const [nextSnapshot, nextHistory] = await Promise.all([getAppSnapshot(), getHistory()]);
      setSnapshot(nextSnapshot); setHistoryEntries(nextHistory); setError(undefined);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeout);
  }, [load]);

  useEffect(() => {
    const refresh = () => void load();
    window.addEventListener("focus", refresh);
    return () => window.removeEventListener("focus", refresh);
  }, [load]);

  useEffect(() => {
    let mounted = true; const unlisteners: Array<() => void> = [];
    void Promise.all([
      listenAppEvent<ScanProgress>("scan-progress", (progress) => {
        if (!mounted) return; setScanProgress(progress); setIsScanning(true);
      }),
      listenAppEvent<ScanReport>("scan-complete", (report) => {
        if (!mounted) return;
        setSnapshot((current) => current ? { ...current, network: report.network, latestReport: report } : current);
        setIsScanning(false); setScanProgress(undefined); setMascotMood("wave"); void getHistory().then(setHistoryEntries);
      }),
      listenAppEvent<ScanReport>("monitor-report", (report) => {
        if (!mounted) return;
        setSnapshot((current) => current ? { ...current, network: report.network, latestReport: report } : current);
        void getHistory().then(setHistoryEntries);
        if (report.devices.some(isUnreviewedNew)) setMascotMood("peek");
      }),
    ]).then((items) => unlisteners.push(...items));
    return () => { mounted = false; unlisteners.forEach((unlisten) => unlisten()); };
  }, []);

  useEffect(() => {
    if (isScanning) return;
    if (mascotMood === "wave") {
      const timeout = window.setTimeout(() => setMascotMood("idle"), 3_200);
      return () => window.clearTimeout(timeout);
    }
    const hasConcern = snapshot?.latestReport?.assessment.risk === "critical" || snapshot?.latestReport?.assessment.risk === "high";
    if (hasConcern) return;
    const motions: MascotMood[] = ["idle", "peek", "scuttle"];
    const timeout = window.setTimeout(() => setMascotMood(motions[Math.floor(Math.random() * motions.length)]), 7_000 + Math.random() * 6_000);
    return () => window.clearTimeout(timeout);
  }, [isScanning, mascotMood, snapshot?.latestReport?.assessment.risk]);

  const startScan = useCallback(async (mode: ScanMode, confirmed = false) => {
    if (mode === "deep" && !confirmed) { setDeepScanDialog(true); return; }
    setDeepScanDialog(false); setError(undefined); setIsScanning(true); setMascotMood("scan");
    setScanProgress({ phase: "start", title: mode === "deep" ? t.scanStart.deep : t.scanStart.safe, detail: t.scanStart.detail, completed: 0, total: 1 });
    try {
      const report = await runScan(mode);
      setSnapshot((current) => current ? { ...current, network: report.network, latestReport: report } : current);
      setHistoryEntries(await getHistory()); setMascotMood("wave");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause)); setMascotMood("concerned");
    } finally {
      setIsScanning(false); setScanProgress(undefined);
    }
  }, [t]);

  useEffect(() => {
    let mounted = true;
    let unlisten: (() => void) | undefined;
    void listenAppEvent<void>("tray-scan-requested", () => {
      if (mounted) void startScan("safe");
    }).then((next) => {
      unlisten = next;
    });
    return () => {
      mounted = false;
      unlisten?.();
    };
  }, [startScan]);

  const changeTrust = useCallback(async (device: ObservedDevice, trust: TrustState) => {
    const networkId = snapshot?.latestReport?.network.networkId;
    if (!networkId) return;
    try {
      await setDeviceTrust(networkId, device.identityKey, trust);
      setSnapshot((current) => {
        if (!current?.latestReport) return current;
        const report = { ...current.latestReport, devices: current.latestReport.devices.map((item) => item.identityKey === device.identityKey ? { ...item, trustState: trust } : item) };
        return { ...current, latestReport: report };
      });
      setSelectedDevice({ ...device, trustState: trust }); setSaved(true); window.setTimeout(() => setSaved(false), 1_600);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
  }, [snapshot?.latestReport?.network.networkId]);

  const changeSettings = useCallback(async (settings: AppSettings) => {
    let desired = settings;
    const enablingNotifications =
      (settings.notifyNewDevices && !snapshot?.settings.notifyNewDevices) ||
      (settings.notifyNetworkChanges && !snapshot?.settings.notifyNetworkChanges);
    if (enablingNotifications) {
      try {
        const granted = await requestNotificationPermission();
        if (!granted) {
          desired = {
            ...settings,
            notifyNewDevices: false,
            notifyNetworkChanges: false,
          };
          setError(t.notificationsDenied);
        }
      } catch (cause) {
        desired = {
          ...settings,
          notifyNewDevices: false,
          notifyNetworkChanges: false,
        };
        setError(cause instanceof Error ? cause.message : String(cause));
      }
    }
    setSnapshot((current) => current ? { ...current, settings: desired } : current);
    try {
      const persisted = await saveSettings(desired);
      setSnapshot((current) => current ? { ...current, settings: persisted } : current);
      setSaved(true); window.setTimeout(() => setSaved(false), 1_600);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
  }, [snapshot?.settings.notifyNetworkChanges, snapshot?.settings.notifyNewDevices, t]);

  const requestLocation = useCallback(async () => {
    setLocationRequestAttempted(true);
    try {
      const permissions = await requestLocationPermission();
      setSnapshot((current) => current ? { ...current, permissions } : current);
      if (permissions.location === "allowed") {
        setNotice(t.locationAllowed);
        setLocationRequestAttempted(false);
      } else if (permissions.location === "denied" || permissions.location === "restricted") {
        setNotice(t.locationDenied);
      } else {
        setNotice(t.locationRequested);
      }
      [800, 2_500, 6_000].forEach((delay) => window.setTimeout(() => void load(), delay));
      window.setTimeout(() => setNotice(undefined), 6_500);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
  }, [load, t]);

  const openSystemSettings = useCallback((section: "location" | "localNetwork") => {
    openPrivacySettings(section).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : String(cause)));
  }, []);

  const openDevice = useCallback((device: ObservedDevice) => { setSelectedDevice(device); setView("devices"); }, []);

  if (!snapshot) return <main className="loading-screen"><div className="loading-mark"><Radar aria-hidden="true" /></div><p>{t.loading}</p></main>;

  const report = snapshot.latestReport;
  const newCount = report?.devices.filter(isUnreviewedNew).length ?? 0;
  const hasHighRisk = report?.assessment.risk === "critical" || report?.assessment.risk === "high";
  const effectiveMascotMood: MascotMood = isScanning ? "scan" : hasHighRisk ? "concerned" : mascotMood;
  const mascotMessage = isScanning ? scanProgress?.title ?? t.mascot.listening
    : effectiveMascotMood === "wave" ? t.mascot.done
      : effectiveMascotMood === "concerned" ? t.mascot.concerned
        : newCount > 0 ? t.mascot.newNeighbors(newCount)
          : snapshot.settings.backgroundMonitoring ? t.mascot.watching : t.mascot.ready;
  const navItems: Array<{ id: View; label: string; icon: LucideIcon; badge?: number }> = [
    { id: "overview", label: t.nav.overview, icon: Gauge },
    { id: "devices", label: t.nav.devices, icon: Network, badge: newCount || undefined },
    { id: "history", label: t.nav.history, icon: History },
    { id: "settings", label: t.nav.settings, icon: Settings, badge: updater.state.available ? 1 : undefined },
  ];
  const needsLocation = snapshot.permissions.location !== "allowed";
  const disconnected = !snapshot.network.connected;

  return (
    <I18nContext.Provider value={t}>
    <div className="app-shell">
      <aside className="sidebar">
        <div className="window-drag-strip" data-tauri-drag-region />
        <div className="brand"><span className="brand__mark"><Radar aria-hidden="true" /></span><span><strong>{t.appName}</strong><small>{t.brandTagline}</small></span></div>
        <nav className="sidebar__nav" aria-label={t.nav.label}>
          {navItems.map((item) => {
            const Icon = item.icon;
            return <button type="button" aria-label={item.label} className={view === item.id ? "is-active" : ""} onClick={() => { setView(item.id); if (item.id !== "devices") setSelectedDevice(undefined); }} key={item.id}>
              <Icon aria-hidden="true" /><span>{item.label}</span>{item.badge && <em>{item.badge}</em>}
            </button>;
          })}
        </nav>
        <div className="sidebar__network"><span className={snapshot.network.connected ? "is-online" : ""} /><div><small>{snapshot.network.connected ? t.sidebar.online : t.sidebar.offline}</small><strong>{snapshot.network.ssid ?? (snapshot.network.connected ? t.sidebar.nameHidden : t.sidebar.notConnected)}</strong></div></div>
        <Mascot mood={effectiveMascotMood} message={mascotMessage} />
      </aside>
      <main className="main-area">
        <header className="topbar" data-tauri-drag-region>
          <div className="topbar__status">
            {isScanning ? <><span className="live-dot" /><span>{scanProgress?.title ?? t.topbar.scanning}</span>{scanProgress && scanProgress.total > 1 && <small>{scanProgress.completed} / {scanProgress.total}</small>}</>
              : <><Clock3 aria-hidden="true" /><span>{report ? t.topbar.checkedAt(formatDate(t, report.completedAt)) : t.topbar.neverChecked}</span></>}
          </div>
          <div className="scan-actions">
            <button type="button" className="scan-button" disabled={isScanning || disconnected} onClick={() => void startScan(snapshot.settings.defaultScanMode)}>
              <RefreshCw className={isScanning ? "is-spinning" : ""} aria-hidden="true" />{isScanning ? t.topbar.scanningShort : t.topbar.scan}
            </button>
            <button type="button" className="scan-menu-button" disabled={isScanning || disconnected} onClick={() => setDeepScanDialog(true)} aria-label={t.topbar.deepScan} title={t.topbar.deepScan}><ChevronDown aria-hidden="true" /></button>
          </div>
        </header>
        <div className="content-scroll">
          {needsLocation && !disconnected && <LocationNotice
            state={snapshot.permissions.location}
            requestAttempted={locationRequestAttempted}
            onRequestLocation={() => void requestLocation()}
            onOpenSettings={() => openSystemSettings("location")}
          />}
          {disconnected ? <DisconnectedState onRetry={() => void load()} />
            : !report && view !== "settings" ? <div className="permission-gate"><div className="permission-gate__visual"><Radar /></div><span className="eyebrow">{t.firstRun.eyebrow}</span><h1>{t.firstRun.title}</h1><p>{t.firstRun.description}</p><button type="button" className="primary-button" onClick={() => void startScan("safe")}><Radar aria-hidden="true" />{t.firstRun.start}</button></div>
              : view === "overview" && report ? <Overview report={report} isScanning={isScanning} onSelectDevice={openDevice} onShowDevices={() => setView("devices")} />
                : view === "devices" && report ? <DevicesView report={report} selectedDevice={selectedDevice} onSelectedDevice={setSelectedDevice} onTrustChange={(device, trust) => void changeTrust(device, trust)} />
                  : view === "history" ? <HistoryView entries={historyEntries} activeReport={report} />
                    : <SettingsView
                        settings={snapshot.settings}
                        permissions={snapshot.permissions}
                        locationRequestAttempted={locationRequestAttempted}
                        update={updater.state}
                        onSettingsChange={(settings) => void changeSettings(settings)}
                        onRequestLocation={() => void requestLocation()}
                        onOpenPrivacySettings={openSystemSettings}
                        onCheckUpdates={() => void updater.checkNow()}
                        onInstallUpdate={() => void updater.install()}
                        onOpenUpdate={updater.openDialog}
                      />}
        </div>
      </main>
      {deepScanDialog && <div className="modal-backdrop" role="presentation" onMouseDown={() => setDeepScanDialog(false)}>
        <section className="modal" role="dialog" aria-modal="true" aria-labelledby="deep-scan-title" onMouseDown={(event) => event.stopPropagation()}>
          <button type="button" className="icon-button modal__close" onClick={() => setDeepScanDialog(false)} aria-label={t.close}><X aria-hidden="true" /></button>
          <span className="modal__icon"><Radar aria-hidden="true" /></span><span className="eyebrow">{t.deepScan.eyebrow}</span><h2 id="deep-scan-title">{t.deepScan.title}</h2>
          <p>{t.deepScan.description}</p>
          <div className="modal__facts"><span><Check aria-hidden="true" /> {t.deepScan.factSubnet}</span><span><Check aria-hidden="true" /> {t.deepScan.factNoExploits}</span><span><Check aria-hidden="true" /> {t.deepScan.factOffline}</span></div>
          <div className="modal__actions"><button type="button" className="secondary-button" onClick={() => setDeepScanDialog(false)}>{t.deepScan.cancel}</button><button type="button" className="primary-button" onClick={() => void startScan("deep", true)}>{t.deepScan.start}</button></div>
        </section>
      </div>}
      <UpdateDialog update={updater.state} onInstall={() => void updater.install()} onClose={updater.dismissDialog} />
      {error && <div className="toast toast--error" role="alert"><AlertTriangle aria-hidden="true" /><span><strong>{t.actionFailed}</strong><small>{error}</small></span><button type="button" onClick={() => setError(undefined)} aria-label={t.close}><X aria-hidden="true" /></button></div>}
      {notice && <div className="toast toast--info" role="status"><Info aria-hidden="true" />{notice}</div>}
      {saved && <div className="toast toast--saved" role="status"><Check aria-hidden="true" />{t.saved}</div>}
    </div>
    </I18nContext.Provider>
  );
}
