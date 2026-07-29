import {
  Activity, AlertTriangle, Bell, Bookmark, Camera, Check, ChevronDown,
  ChevronRight, CircleCheck, CircleHelp, Clock3, Eye, Gauge, History, Info,
  Download, Laptop, Lock, MapPin, Network, Printer, Radar, Radio, RefreshCw,
  Router, Search, Settings, ShieldCheck, Signal, SlidersHorizontal, Smartphone,
  Tablet, Tv, UserCheck, Wifi, X, type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import {
  getAppSnapshot, getHistory, listenAppEvent, openPrivacySettings,
  requestLocationPermission, requestNotificationPermission, runScan,
  saveSettings, setDeviceTrust,
} from "./api";
import crabImage from "./assets/mayak-crab.png";
import type {
  AppSettings, AppSnapshot, Confidence, DeviceKind, Finding, HistoryEntry,
  ObservedDevice, PermissionState, ScanMode, ScanProgress, ScanReport, Severity,
  TrustState, VisibilityLevel,
} from "./types";
import { useAppUpdater, type AppUpdateState } from "./useAppUpdater";

type View = "overview" | "devices" | "history" | "settings";
type MascotMood = "idle" | "peek" | "scuttle" | "scan" | "wave" | "concerned";

const severityMeta: Record<Severity, { label: string; className: string; icon: LucideIcon }> = {
  good: { label: "В порядке", className: "tone-good", icon: CircleCheck },
  info: { label: "К сведению", className: "tone-info", icon: Info },
  warning: { label: "Стоит проверить", className: "tone-warning", icon: AlertTriangle },
  high: { label: "Высокий риск", className: "tone-danger", icon: AlertTriangle },
  critical: { label: "Критический риск", className: "tone-critical", icon: AlertTriangle },
};

const deviceKindMeta: Record<DeviceKind, { label: string; icon: LucideIcon }> = {
  router: { label: "Маршрутизатор", icon: Router },
  computer: { label: "Компьютер", icon: Laptop },
  phone: { label: "Телефон", icon: Smartphone },
  tablet: { label: "Планшет", icon: Tablet },
  printer: { label: "Принтер", icon: Printer },
  media: { label: "Медиаустройство", icon: Tv },
  smartHome: { label: "Умный дом", icon: Radio },
  camera: { label: "Камера", icon: Camera },
  possibleCamera: { label: "Возможная камера", icon: Eye },
  networkEquipment: { label: "Сетевое оборудование", icon: Network },
  unknown: { label: "Неизвестно", icon: CircleHelp },
};

const trustMeta: Record<TrustState, { label: string; icon: LucideIcon }> = {
  unknown: { label: "Не отмечено", icon: CircleHelp },
  mine: { label: "Моё устройство", icon: UserCheck },
  known: { label: "Знакомое", icon: Bookmark },
  ignored: { label: "Игнорировать", icon: Eye },
};

function isUnreviewedNew(device: ObservedDevice) {
  return device.isNew && device.trustState === "unknown" && device.kind !== "router";
}

const visibilityMeta: Record<VisibilityLevel, { label: string; description: string }> = {
  good: { label: "Хорошая", description: "Большинство доступных способов обнаружения сработали." },
  partial: { label: "Частичная", description: "Некоторые устройства могут быть скрыты настройками сети." },
  limited: { label: "Ограниченная", description: "Сеть существенно ограничивает обзор соседних устройств." },
};

const confidenceLabel: Record<Confidence, string> = {
  high: "высокая", medium: "средняя", low: "низкая",
};

function formatDate(value: string, withDate = false) {
  return new Intl.DateTimeFormat("ru-RU", {
    day: withDate ? "numeric" : undefined,
    month: withDate ? "short" : undefined,
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function formatDuration(ms: number) {
  if (ms < 1_000) return `${ms} мс`;
  return `${(ms / 1_000).toFixed(1).replace(".", ",")} с`;
}

function formatBytes(value: number) {
  if (value < 1_024) return `${value} Б`;
  if (value < 1_048_576) return `${Math.round(value / 1_024)} КБ`;
  return `${(value / 1_048_576).toFixed(1).replace(".", ",")} МБ`;
}

function normalizeSecurity(value: string) {
  const labels: Record<string, string> = {
    open: "Открытая сеть", wep: "WEP", "wpa-personal": "WPA Personal",
    "wpa2-personal": "WPA2 Personal", "wpa3-personal": "WPA3 Personal",
    "wpa2-wpa3-transition": "WPA2 / WPA3", "wpa-enterprise": "WPA Enterprise",
    "wpa2-enterprise": "WPA2 Enterprise", "wpa3-enterprise": "WPA3 Enterprise",
    owe: "Enhanced Open (OWE)", unknown: "Не удалось определить",
  };
  return labels[value] ?? value.replaceAll("-", " ").toUpperCase();
}

function permissionLabel(state: PermissionState) {
  return ({
    allowed: "Разрешено", notDetermined: "Ещё не запрошено", denied: "Запрещено",
    restricted: "Ограничено системой", unknown: "Не определено",
  } satisfies Record<PermissionState, string>)[state];
}

function DeviceIcon({ kind, size = "regular" }: {
  kind: DeviceKind; size?: "small" | "regular" | "large";
}) {
  const Icon = deviceKindMeta[kind].icon;
  return <span className={`device-icon device-icon--${kind} device-icon--${size}`}><Icon aria-hidden="true" /></span>;
}

function StatusPill({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  const meta = severityMeta[severity];
  const Icon = meta.icon;
  return (
    <span className={`status-pill ${meta.className} ${compact ? "is-compact" : ""}`}>
      <Icon aria-hidden="true" />{meta.label}
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
    <div className={`topology ${isScanning ? "is-scanning" : ""}`} aria-label="Радар обнаруженных устройств">
      <div className="topology__caption"><strong>Радар обнаружения</strong><span>Кольца показывают уверенность в типе, не расстояние</span></div>
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
        const Icon = deviceKindMeta[device.kind].icon;
        return (
          <button
            type="button"
            className={`topology__device ${isUnreviewedNew(device) ? "is-new" : ""}`}
            key={device.identityKey}
            style={style}
            data-confidence={device.typeConfidence}
            onClick={() => onSelectDevice(device)}
            aria-label={`${device.displayName}, ${deviceKindMeta[device.kind].label}`}
          >
            <Icon aria-hidden="true" />
            <span className="topology__device-label">{device.displayName}</span>
          </button>
        );
      })}
      </div>
      <div className="topology__legend" aria-hidden="true">
        <span><i data-confidence="high" />тип подтверждён</span>
        <span><i data-confidence="medium" />тип вероятен</span>
        <span><i data-confidence="low" />тип не определён</span>
      </div>
      {report.devices.length > 8 && <div className="topology__more">+{report.devices.length - 8} в списке</div>}
    </div>
  );
}

function FindingRow({ finding, defaultOpen = false }: { finding: Finding; defaultOpen?: boolean }) {
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
            <div><span className="eyebrow">Основание вывода</span><ul>
              {finding.evidence.map((item) => <li key={item}>{item}</li>)}
            </ul></div>
          )}
        </div>
      )}
    </article>
  );
}

function NetworkFacts({ report }: { report: ScanReport }) {
  const { network, coverage } = report;
  const facts = [
    ["Интерфейс", network.interfaceName ?? "—"], ["BSSID", network.bssid ?? "Скрыт системой"],
    ["IPv4", network.ipv4 ?? "—"], ["Подсеть", network.subnet ?? "—"],
    ["Шлюз", network.router ?? "—"], ["DNS", network.dnsServers.join(", ") || "—"],
    ["Диапазон", network.channel?.band ?? "—"],
    ["Канал", network.channel ? `${network.channel.number} · ${network.channel.width}` : "—"],
    ["Режим", network.phyMode ?? "—"],
    ["Скорость PHY", network.transmitRateMbps ? `${network.transmitRateMbps} Мбит/с` : "—"],
    ["RSSI / шум", network.rssi ? `${network.rssi} / ${network.noise ?? "—"} dBm` : "—"],
    ["Страна", network.countryCode ?? "—"], ["IPv6", network.ipv6.join(", ") || "—"],
    ["Прокси", network.proxyEnabled ? "Включён" : "Не обнаружен"],
    ["VPN", network.vpnActive ? "Активен" : "Не обнаружен"],
  ];
  return (
    <details className="technical-panel">
      <summary><span><SlidersHorizontal aria-hidden="true" />Все параметры сети</span><ChevronDown aria-hidden="true" /></summary>
      <div className="technical-panel__body">
        <dl className="facts">{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
        <div className="coverage-detail">
          <div><span className="eyebrow">Способы обнаружения</span><p>{coverage.methods.join(" · ")}</p></div>
          <div><span className="eyebrow">Охват</span><p>
            Проверено {coverage.targetCount} адресов · ответили {coverage.responsiveCount} · ARP {coverage.arpCount}
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
  const risk = severityMeta[report.assessment.risk];
  const RiskIcon = risk.icon;
  const newDevices = report.devices.filter(isUnreviewedNew).length;
  const concerning = report.devices.filter((device) => device.kind === "camera" || device.kind === "possibleCamera").length;
  return (
    <div className="view-stack overview">
      <section className="network-hero">
        <div className="network-hero__copy">
          <span className="eyebrow">Текущая Wi-Fi-сеть</span>
          <div className="network-title"><h1>{report.network.ssid ?? "Сеть без имени"}</h1><StatusPill severity={report.assessment.risk} /></div>
          <div className={`verdict ${risk.className}`}>
            <span className="verdict__icon"><RiskIcon aria-hidden="true" /></span>
            <div><h2>{report.assessment.summary}</h2><p>
              Маяк разделяет риск сети и полноту обзора: невидимое устройство не означает, что его нет.
            </p></div>
          </div>
          <div className="network-signal">
            <Signal aria-hidden="true" /><div><strong>{report.network.signalQuality ?? "—"}%</strong><span>сигнал</span></div>
            <span className="network-signal__divider" />
            <Lock aria-hidden="true" /><div><strong>{normalizeSecurity(report.network.security)}</strong><span>защита Wi-Fi</span></div>
          </div>
        </div>
        <Topology report={report} isScanning={isScanning} onSelectDevice={onSelectDevice} />
      </section>
      <section className="metric-rail" aria-label="Итоги проверки">
        <button type="button" onClick={onShowDevices}><span className="metric-rail__icon metric-rail__icon--accent"><Radar aria-hidden="true" /></span><span><strong>{report.devices.length}</strong><small>устройств видно</small></span><ChevronRight aria-hidden="true" /></button>
        <button type="button" onClick={onShowDevices}><span className="metric-rail__icon metric-rail__icon--new"><Activity aria-hidden="true" /></span><span><strong>{newDevices}</strong><small>новых без отметки</small></span><ChevronRight aria-hidden="true" /></button>
        <div><span className="metric-rail__icon"><Eye aria-hidden="true" /></span><span><strong>{visibilityMeta[report.assessment.visibility].label}</strong><small>видимость сети</small></span></div>
        <div className={concerning > 0 ? "is-concerning" : ""}><span className="metric-rail__icon"><Camera aria-hidden="true" /></span><span><strong>{concerning || "Нет"}</strong><small>{concerning ? "нужно проверить" : "признаков камер"}</small></span></div>
      </section>
      <section className="content-section">
        <div className="section-heading"><div><span className="eyebrow">Разбор результата</span><h2>Что важно знать</h2></div><span className="section-heading__meta">Уверенность: {confidenceLabel[report.assessment.confidence]}</span></div>
        <div className="findings">{report.assessment.findings.map((finding, index) => (
          <FindingRow finding={finding} defaultOpen={index === 0 && finding.severity !== "good"} key={finding.id} />
        ))}</div>
      </section>
      <NetworkFacts report={report} />
      <p className="scan-footnote">Проверка завершена в {formatDate(report.completedAt)} за {formatDuration(report.durationMs)} · режим {report.mode === "deep" ? "углублённый" : "безопасный"}</p>
    </div>
  );
}

function DeviceDetails({ device, onClose, onTrustChange }: {
  device: ObservedDevice; onClose: () => void; onTrustChange: (trust: TrustState) => void;
}) {
  const kind = deviceKindMeta[device.kind];
  return (
    <aside className="device-drawer" aria-label={`Сведения: ${device.displayName}`}>
      <div className="device-drawer__header">
        <DeviceIcon kind={device.kind} size="large" />
        <div><span className="eyebrow">{kind.label}</span><h2>{device.displayName}</h2></div>
        <button type="button" className="icon-button" onClick={onClose} aria-label="Закрыть"><X aria-hidden="true" /></button>
      </div>
      {(device.kind === "camera" || device.kind === "possibleCamera") && (
        <div className="device-alert"><AlertTriangle aria-hidden="true" /><div>
          <strong>{device.kind === "camera" ? "Обнаружены признаки IP-камеры" : "Есть признаки, совместимые с камерой"}</strong>
          <p>Это техническая гипотеза, а не доказательство скрытого наблюдения. Сверьте производителя, имя и сервисы.</p>
        </div></div>
      )}
      <div className="trust-selector"><span className="eyebrow">Как вы знаете устройство</span><div>
        {(["unknown", "mine", "known", "ignored"] as TrustState[]).map((trust) => {
          const Icon = trustMeta[trust].icon;
          return <button type="button" className={device.trustState === trust ? "is-selected" : ""} key={trust} onClick={() => onTrustChange(trust)}>
            <Icon aria-hidden="true" />{trustMeta[trust].label}{device.trustState === trust && <Check aria-hidden="true" />}
          </button>;
        })}
      </div></div>
      <dl className="device-facts">
        <div><dt>IP-адреса</dt><dd>{device.ipAddresses.join(", ")}</dd></div>
        <div><dt>MAC-адрес</dt><dd>{device.macAddress ?? "Не виден"}</dd></div>
        <div><dt>Производитель</dt><dd>{device.vendor ?? "Не определён"}</dd></div>
        <div><dt>Имена</dt><dd>{device.hostnames.join(", ") || "Не объявлены"}</dd></div>
        <div><dt>Открытые порты</dt><dd>{device.openPorts.join(", ") || "Не найдены"}</dd></div>
        <div><dt>Впервые замечено</dt><dd>{formatDate(device.firstSeen, true)}</dd></div>
        <div><dt>Последний ответ</dt><dd>{formatDate(device.lastSeen, true)}</dd></div>
        <div><dt>Уверенность в типе</dt><dd>{confidenceLabel[device.typeConfidence]}</dd></div>
      </dl>
      {device.services.length > 0 && <section className="device-services"><span className="eyebrow">Объявленные сервисы</span>
        {device.services.map((service, index) => <div key={`${service.protocol}-${service.name}-${index}`}><Radio aria-hidden="true" /><span>
          <strong>{service.name}</strong><small>{service.protocol.toUpperCase()}{service.serviceType ? ` · ${service.serviceType}` : ""}{service.port ? ` · порт ${service.port}` : ""}</small>
        </span></div>)}
      </section>}
      <section className="device-evidence"><span className="eyebrow">Почему Маяк видит это устройство</span><ul>
        {device.evidence.map((item) => <li key={item}>{item}</li>)}
      </ul></section>
    </aside>
  );
}

function DevicesView({ report, selectedDevice, onSelectedDevice, onTrustChange }: {
  report: ScanReport; selectedDevice?: ObservedDevice; onSelectedDevice: (device?: ObservedDevice) => void;
  onTrustChange: (device: ObservedDevice, trust: TrustState) => void;
}) {
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
        <div className="page-heading"><div><span className="eyebrow">Текущая сеть</span><h1>Видимые устройства</h1><p>
          Маяк показывает наблюдаемые признаки и отдельно отмечает уровень уверенности.
        </p></div><span className="count-badge">{report.devices.length}</span></div>
        <div className="device-tools">
          <label className="search-field"><Search aria-hidden="true" /><span className="sr-only">Найти устройство</span>
            <input type="search" placeholder="Имя, IP, MAC или производитель" value={query} onChange={(event) => setQuery(event.target.value)} />
            {query && <button type="button" onClick={() => setQuery("")} aria-label="Очистить поиск"><X aria-hidden="true" /></button>}
          </label>
          <div className="filter-tabs" aria-label="Фильтр устройств">
            {([["all", "Все"], ["new", "Новые"], ["attention", "Проверить"], ["known", "Знакомые"]] as const).map(([value, label]) => (
              <button type="button" className={filter === value ? "is-active" : ""} onClick={() => setFilter(value)} key={value}>{label}</button>
            ))}
          </div>
        </div>
        <div className="device-list">
          <div className="device-list__header" aria-hidden="true"><span>Устройство</span><span>Адрес</span><span>Наблюдения</span><span>Статус</span></div>
          {devices.map((device) => {
            const isConcern = device.kind === "camera" || device.kind === "possibleCamera" ||
              device.findings.some((item) => ["warning", "high", "critical"].includes(item.severity));
            return <button type="button" className={`device-row ${selectedDevice?.identityKey === device.identityKey ? "is-selected" : ""}`} key={device.identityKey} onClick={() => onSelectedDevice(device)}>
              <span className="device-row__name"><DeviceIcon kind={device.kind} /><span><strong>{device.displayName}</strong><small>{deviceKindMeta[device.kind].label}{device.vendor ? ` · ${device.vendor}` : ""}</small></span></span>
              <span className="device-row__address"><span><strong>{device.ipAddresses[0] ?? "—"}</strong><small>{device.macAddress ?? "MAC не виден"}</small></span></span>
              <span className="device-row__evidence"><span><strong>{device.openPorts.length ? `Порты ${device.openPorts.slice(0, 4).join(", ")}` : "Открытые порты не найдены"}</strong><small>{device.services.length ? `${device.services.length} сервиса` : `Тип: уверенность ${confidenceLabel[device.typeConfidence]}`}</small></span></span>
              <span className="device-row__status">
                {isConcern ? <span className="mini-tag mini-tag--warning"><AlertTriangle aria-hidden="true" />Проверить</span>
                  : isUnreviewedNew(device) ? <span className="mini-tag mini-tag--new">Новое</span>
                    : device.trustState !== "unknown" ? <span className="mini-tag">{trustMeta[device.trustState].label}</span>
                      : <span className="mini-tag mini-tag--quiet">Наблюдается</span>}
                <ChevronRight aria-hidden="true" />
              </span>
            </button>;
          })}
          {devices.length === 0 && <div className="empty-state"><Search aria-hidden="true" /><h2>Ничего не найдено</h2><p>Измените запрос или выберите другой фильтр.</p></div>}
        </div>
      </div>
      {selectedDevice && <DeviceDetails device={selectedDevice} onClose={() => onSelectedDevice(undefined)} onTrustChange={(trust) => onTrustChange(selectedDevice, trust)} />}
    </div>
  );
}

function HistoryView({ entries, activeReport }: { entries: HistoryEntry[]; activeReport?: ScanReport }) {
  return (
    <div className="view-stack">
      <div className="page-heading"><div><span className="eyebrow">Только на этом компьютере</span><h1>История наблюдений</h1><p>
        Сравнивайте знакомые сети и замечайте изменения точки доступа или состава устройств.
      </p></div></div>
      <section className="history-timeline">
        {entries.map((entry) => {
          const meta = severityMeta[entry.risk]; const Icon = meta.icon; const isCurrent = entry.id === activeReport?.id;
          return <article className={isCurrent ? "is-current" : ""} key={entry.id}>
            <div className={`history-timeline__marker ${meta.className}`}><Icon aria-hidden="true" /></div>
            <div className="history-timeline__content"><div>
              <span className="history-timeline__date">{formatDate(entry.completedAt, true)}{isCurrent && <em>текущая</em>}</span>
              <h2>{entry.ssid ?? "Сеть без имени"}</h2><p>{normalizeSecurity(entry.security)}</p>
            </div><div className="history-timeline__stats">
              <span><strong>{entry.deviceCount}</strong> устройств</span><span><strong>{entry.newDeviceCount}</strong> новых</span>
              <span><strong>{visibilityMeta[entry.visibility].label}</strong> видимость</span><StatusPill severity={entry.risk} compact />
            </div></div>
          </article>;
        })}
        {entries.length === 0 && <div className="empty-state"><History aria-hidden="true" /><h2>История пока пуста</h2><p>Первая запись появится после завершённой проверки.</p></div>}
      </section>
      <div className="privacy-note"><ShieldCheck aria-hidden="true" /><div><strong>История остаётся локальной</strong><p>
        Маяк не отправляет имена сетей, адреса и сведения об устройствах в облако.
      </p></div></div>
    </div>
  );
}

function UpdateSettings({ update, onCheck, onInstall, onOpen }: {
  update: AppUpdateState;
  onCheck: () => void;
  onInstall: () => void;
  onOpen: () => void;
}) {
  const isBusy = update.phase === "checking" ||
    update.phase === "downloading" ||
    update.phase === "installing" ||
    update.phase === "restarting";
  const status = update.phase === "checking" ? "Проверяем GitHub Releases…"
    : update.phase === "available" ? `Доступна версия ${update.available?.version}`
      : update.phase === "downloading" ? `Загружено ${formatBytes(update.downloadedBytes)}`
        : update.phase === "installing" ? "Проверяем подпись и устанавливаем…"
          : update.phase === "restarting" ? "Перезапускаем Маяк…"
            : update.phase === "current" ? "Установлена последняя версия"
              : update.phase === "failed" ? update.error
                : "Проверяем при запуске и затем каждые 6 часов";
  const action = update.available
    ? update.phase === "available" || update.phase === "failed"
      ? <button type="button" className="secondary-button" onClick={update.phase === "failed" ? onInstall : onOpen}>
          {update.phase === "failed" ? "Повторить установку" : "Посмотреть"}
        </button>
      : <button type="button" className="secondary-button" disabled>Выполняется…</button>
    : <button type="button" className="secondary-button" disabled={isBusy} onClick={onCheck}>
        <RefreshCw className={update.phase === "checking" ? "is-spinning" : ""} aria-hidden="true" />
        {update.phase === "checking" ? "Проверяем…" : "Проверить"}
      </button>;
  return (
    <section className="settings-group">
      <div className="settings-group__heading"><Download aria-hidden="true" /><div><h2>Обновления</h2><p>Только подписанные пакеты из официального GitHub Releases.</p></div></div>
      <div className="permission-row"><span><strong>Версия Маяка</strong><small>{update.installedVersion ?? "Определяем…"}</small></span>{action}</div>
      <div className={`update-status update-status--${update.phase}`}>
        <ShieldCheck aria-hidden="true" />
        <span><strong>{status}</strong>{update.lastCheckedAt && <small>Последняя проверка: {formatDate(update.lastCheckedAt, true)}</small>}</span>
      </div>
    </section>
  );
}

function SettingsView({ settings, permissions, locationRequestAttempted, update, onSettingsChange, onRequestLocation, onCheckUpdates, onInstallUpdate, onOpenUpdate }: {
  settings: AppSettings; permissions: AppSnapshot["permissions"]; locationRequestAttempted: boolean;
  update: AppUpdateState;
  onSettingsChange: (settings: AppSettings) => void; onRequestLocation: () => void;
  onCheckUpdates: () => void; onInstallUpdate: () => void; onOpenUpdate: () => void;
}) {
  const patch = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => onSettingsChange({ ...settings, [key]: value });
  return (
    <div className="view-stack settings-view">
      <div className="page-heading"><div><span className="eyebrow">Поведение Маяка</span><h1>Настройки</h1><p>
        Фоновая проверка работает локально и только в текущей Wi-Fi-сети.
      </p></div></div>
      <section className="settings-group">
        <div className="settings-group__heading"><Radar aria-hidden="true" /><div><h2>Наблюдение</h2><p>Замечает новые устройства без постоянно открытого окна.</p></div></div>
        <label className="setting-row"><span><strong>Фоновое наблюдение</strong><small>Проверять сеть через заданный интервал</small></span>
          <input type="checkbox" className="switch" checked={settings.backgroundMonitoring} onChange={(event) => patch("backgroundMonitoring", event.target.checked)} /></label>
        <label className="setting-row"><span><strong>Интервал</strong><small>Чем чаще, тем быстрее Маяк заметит изменение</small></span>
          <select value={settings.monitoringIntervalSeconds} disabled={!settings.backgroundMonitoring} onChange={(event) => patch("monitoringIntervalSeconds", Number(event.target.value))}>
            <option value={60}>Каждую минуту</option><option value={300}>Каждые 5 минут</option><option value={900}>Каждые 15 минут</option><option value={1800}>Каждые 30 минут</option>
          </select></label>
        <label className="setting-row"><span><strong>Обычный режим проверки</strong><small>Углублённый режим проверяет больше адресов и портов</small></span>
          <select value={settings.defaultScanMode} onChange={(event) => patch("defaultScanMode", event.target.value as ScanMode)}>
            <option value="safe">Безопасный</option><option value="deep">Углублённый</option>
          </select></label>
      </section>
      <section className="settings-group">
        <div className="settings-group__heading"><Bell aria-hidden="true" /><div><h2>Сигналы</h2><p>Только значимые изменения — без постоянного шума.</p></div></div>
        <label className="setting-row"><span><strong>Новое устройство</strong><small>Сообщать о новом соседе в знакомой сети</small></span>
          <input type="checkbox" className="switch" checked={settings.notifyNewDevices} onChange={(event) => patch("notifyNewDevices", event.target.checked)} /></label>
        <label className="setting-row"><span><strong>Изменилась сеть</strong><small>Новый BSSID, шлюз или тип защиты</small></span>
          <input type="checkbox" className="switch" checked={settings.notifyNetworkChanges} onChange={(event) => patch("notifyNetworkChanges", event.target.checked)} /></label>
      </section>
      <UpdateSettings update={update} onCheck={onCheckUpdates} onInstall={onInstallUpdate} onOpen={onOpenUpdate} />
      <section className="settings-group">
        <div className="settings-group__heading"><MapPin aria-hidden="true" /><div><h2>Системный доступ</h2><p>Геопозиция раскрывает только SSID/BSSID; сканирование работает без неё.</p></div></div>
        <div className="permission-row"><span><strong>Службы геолокации</strong><small>{permissionLabel(permissions.location)}</small></span>
          {permissions.location === "notDetermined" && !locationRequestAttempted ? <button type="button" className="secondary-button" onClick={onRequestLocation}>Разрешить</button>
            : permissions.location !== "allowed" ? <button type="button" className="secondary-button" onClick={() => void openPrivacySettings("location")}>Открыть настройки</button>
              : <span className="permission-ok"><Check aria-hidden="true" /> Разрешено</span>}</div>
        <div className="permission-row"><span><strong>Локальная сеть</strong><small>{permissionLabel(permissions.localNetwork)}</small></span>
          {permissions.localNetwork !== "allowed" ? <button type="button" className="secondary-button" onClick={() => void openPrivacySettings("localNetwork")}>Открыть настройки</button>
            : <span className="permission-ok"><Check aria-hidden="true" /> Разрешено</span>}</div>
      </section>
    </div>
  );
}

function UpdateDialog({ update, onInstall, onClose }: {
  update: AppUpdateState;
  onInstall: () => void;
  onClose: () => void;
}) {
  const available = update.available;
  if (!available || !update.dialogOpen) return null;

  const isBusy = update.phase === "downloading" ||
    update.phase === "installing" ||
    update.phase === "restarting";
  const percentage = update.totalBytes && update.totalBytes > 0
    ? Math.min(100, Math.round(update.downloadedBytes / update.totalBytes * 100))
    : undefined;
  const progressLabel = update.phase === "downloading"
    ? `Загружаем${percentage === undefined ? "…" : `: ${percentage}%`}`
    : update.phase === "installing" ? "Устанавливаем подписанное обновление…"
      : update.phase === "restarting" ? "Перезапускаем Маяк…"
        : undefined;

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={isBusy ? undefined : onClose}>
      <section className="modal update-modal" role="dialog" aria-modal="true" aria-labelledby="update-title" onMouseDown={(event) => event.stopPropagation()}>
        {!isBusy && <button type="button" className="icon-button modal__close" onClick={onClose} aria-label="Закрыть"><X aria-hidden="true" /></button>}
        <span className="modal__icon"><Download aria-hidden="true" /></span>
        <span className="eyebrow">Подписанное обновление</span>
        <h2 id="update-title">Маяк {available.version}</h2>
        <p>Установлена версия {available.currentVersion}. Маяк проверит подпись пакета до любых изменений и перезапустится только после установки.</p>
        {available.notes && <div className="update-notes"><span className="eyebrow">Что изменилось</span><p>{available.notes}</p></div>}
        <div className="modal__facts">
          <span><ShieldCheck aria-hidden="true" /> Пакет подписан ключом проекта</span>
          <span><Check aria-hidden="true" /> Загрузка только по HTTPS из GitHub Releases</span>
          <span><RefreshCw aria-hidden="true" /> Перезапуск после успешной установки</span>
        </div>
        {progressLabel && <div className="update-progress" aria-live="polite">
          <div><span>{progressLabel}</span>{update.totalBytes && <small>{formatBytes(update.downloadedBytes)} из {formatBytes(update.totalBytes)}</small>}</div>
          <progress value={percentage} max={100} />
        </div>}
        {update.error && <p className="update-error" role="alert">{update.error}</p>}
        <div className="modal__actions">
          {!isBusy && <button type="button" className="secondary-button" onClick={onClose}>Позже</button>}
          <button type="button" className="primary-button" disabled={isBusy} onClick={onInstall}>
            <Download aria-hidden="true" />{isBusy ? "Обновляем…" : update.phase === "failed" ? "Повторить" : "Установить и перезапустить"}
          </button>
        </div>
      </section>
    </div>
  );
}

function LocationNotice({ state, requestAttempted, onRequestLocation, onOpenSettings }: {
  state: PermissionState; requestAttempted: boolean; onRequestLocation: () => void; onOpenSettings: () => void;
}) {
  const canRequest = state === "notDetermined" && !requestAttempted;
  return (
    <aside className="permission-notice" aria-label="Имя Wi-Fi скрыто системой">
      <span className="permission-notice__icon"><MapPin aria-hidden="true" /></span>
      <div><strong>{requestAttempted ? "Запрос отправлен системе" : "Имя Wi-Fi пока скрыто системой"}</strong><p>
        {requestAttempted
          ? "Если системное окно не появилось, разрешите геопозицию в настройках. Сканирование уже работает."
          : "Проверка устройств уже работает. Доступ нужен только для SSID и BSSID; координаты Маяк не получает."}
      </p></div>
      <button type="button" className="secondary-button" onClick={canRequest ? onRequestLocation : onOpenSettings}>
        {canRequest ? "Показать имя сети" : "Открыть настройки"}
      </button>
    </aside>
  );
}

function DisconnectedState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="permission-gate">
      <div className="permission-gate__visual permission-gate__visual--quiet"><Wifi /></div>
      <span className="eyebrow">Нет активной Wi-Fi-сети</span><h1>Подключитесь к сети</h1>
      <p>Как только Wi-Fi появится, Маяк прочитает его параметры и сможет безопасно проверить локальное окружение.</p>
      <button type="button" className="primary-button" onClick={onRetry}><RefreshCw aria-hidden="true" />Проверить ещё раз</button>
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
    setScanProgress({ phase: "start", title: mode === "deep" ? "Начинаем углублённую проверку" : "Начинаем проверку", detail: "Готовим безопасные локальные запросы", completed: 0, total: 1 });
    try {
      const report = await runScan(mode);
      setSnapshot((current) => current ? { ...current, network: report.network, latestReport: report } : current);
      setHistoryEntries(await getHistory()); setMascotMood("wave");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause)); setMascotMood("concerned");
    } finally {
      setIsScanning(false); setScanProgress(undefined);
    }
  }, []);

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
          setError("Система не разрешила уведомления. Их можно включить позже в настройках.");
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
  }, [snapshot?.settings.notifyNetworkChanges, snapshot?.settings.notifyNewDevices]);

  const requestLocation = useCallback(async () => {
    setLocationRequestAttempted(true);
    try {
      const permissions = await requestLocationPermission();
      setSnapshot((current) => current ? { ...current, permissions } : current);
      if (permissions.location === "allowed") {
        setNotice("Имя текущей Wi-Fi-сети теперь доступно.");
        setLocationRequestAttempted(false);
      } else if (permissions.location === "denied" || permissions.location === "restricted") {
        setNotice("Доступ отключён в системе. Откройте настройки, чтобы изменить его.");
      } else {
        setNotice("Запрос отправлен. Если система не показала окно, нажмите «Открыть настройки».");
      }
      [800, 2_500, 6_000].forEach((delay) => window.setTimeout(() => void load(), delay));
      window.setTimeout(() => setNotice(undefined), 6_500);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
  }, [load]);

  const openDevice = useCallback((device: ObservedDevice) => { setSelectedDevice(device); setView("devices"); }, []);

  if (!snapshot) return <main className="loading-screen"><div className="loading-mark"><Radar aria-hidden="true" /></div><p>Настраиваем Маяк…</p></main>;

  const report = snapshot.latestReport;
  const newCount = report?.devices.filter(isUnreviewedNew).length ?? 0;
  const hasHighRisk = report?.assessment.risk === "critical" || report?.assessment.risk === "high";
  const effectiveMascotMood: MascotMood = isScanning ? "scan" : hasHighRisk ? "concerned" : mascotMood;
  const mascotMessage = isScanning ? scanProgress?.title ?? "Слушаю сеть…"
    : effectiveMascotMood === "wave" ? "Готово! Я всё разложил."
      : effectiveMascotMood === "concerned" ? "Тут есть что проверить."
        : newCount > 0 ? `${newCount} ${newCount === 1 ? "новый сосед" : "новых соседа"}`
          : snapshot.settings.backgroundMonitoring ? "Я присматриваю за сетью." : "Готов проверить сеть.";
  const navItems: Array<{ id: View; label: string; icon: LucideIcon; badge?: number }> = [
    { id: "overview", label: "Обзор", icon: Gauge },
    { id: "devices", label: "Устройства", icon: Network, badge: newCount || undefined },
    { id: "history", label: "История", icon: History },
    { id: "settings", label: "Настройки", icon: Settings, badge: updater.state.available ? 1 : undefined },
  ];
  const needsLocation = snapshot.permissions.location !== "allowed";
  const disconnected = !snapshot.network.connected;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="window-drag-strip" data-tauri-drag-region />
        <div className="brand"><span className="brand__mark"><Radar aria-hidden="true" /></span><span><strong>Маяк</strong><small>локальная безопасность</small></span></div>
        <nav className="sidebar__nav" aria-label="Разделы">
          {navItems.map((item) => {
            const Icon = item.icon;
            return <button type="button" aria-label={item.label} className={view === item.id ? "is-active" : ""} onClick={() => { setView(item.id); if (item.id !== "devices") setSelectedDevice(undefined); }} key={item.id}>
              <Icon aria-hidden="true" /><span>{item.label}</span>{item.badge && <em>{item.badge}</em>}
            </button>;
          })}
        </nav>
        <div className="sidebar__network"><span className={snapshot.network.connected ? "is-online" : ""} /><div><small>{snapshot.network.connected ? "Сейчас в сети" : "Нет Wi-Fi"}</small><strong>{snapshot.network.ssid ?? (snapshot.network.connected ? "Имя скрыто системой" : "Не подключено")}</strong></div></div>
        <Mascot mood={effectiveMascotMood} message={mascotMessage} />
      </aside>
      <main className="main-area">
        <header className="topbar" data-tauri-drag-region>
          <div className="topbar__status">
            {isScanning ? <><span className="live-dot" /><span>{scanProgress?.title ?? "Проверяем сеть"}</span>{scanProgress && scanProgress.total > 1 && <small>{scanProgress.completed} / {scanProgress.total}</small>}</>
              : <><Clock3 aria-hidden="true" /><span>{report ? `Проверено ${formatDate(report.completedAt)}` : "Сеть ещё не проверялась"}</span></>}
          </div>
          <div className="scan-actions">
            <button type="button" className="scan-button" disabled={isScanning || disconnected} onClick={() => void startScan(snapshot.settings.defaultScanMode)}>
              <RefreshCw className={isScanning ? "is-spinning" : ""} aria-hidden="true" />{isScanning ? "Проверяем…" : "Проверить сеть"}
            </button>
            <button type="button" className="scan-menu-button" disabled={isScanning || disconnected} onClick={() => setDeepScanDialog(true)} aria-label="Углублённая проверка" title="Углублённая проверка"><ChevronDown aria-hidden="true" /></button>
          </div>
        </header>
        <div className="content-scroll">
          {needsLocation && !disconnected && <LocationNotice
            state={snapshot.permissions.location}
            requestAttempted={locationRequestAttempted}
            onRequestLocation={() => void requestLocation()}
            onOpenSettings={() => void openPrivacySettings("location")}
          />}
          {disconnected ? <DisconnectedState onRetry={() => void load()} />
            : !report && view !== "settings" ? <div className="permission-gate"><div className="permission-gate__visual"><Radar /></div><span className="eyebrow">Всё готово</span><h1>Познакомимся с этой сетью?</h1><p>Первая безопасная проверка соберёт параметры Wi-Fi и доступные признаки соседних устройств — даже если имя сети скрыто системой.</p><button type="button" className="primary-button" onClick={() => void startScan("safe")}><Radar aria-hidden="true" />Начать проверку</button></div>
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
                        onCheckUpdates={() => void updater.checkNow()}
                        onInstallUpdate={() => void updater.install()}
                        onOpenUpdate={updater.openDialog}
                      />}
        </div>
      </main>
      {deepScanDialog && <div className="modal-backdrop" role="presentation" onMouseDown={() => setDeepScanDialog(false)}>
        <section className="modal" role="dialog" aria-modal="true" aria-labelledby="deep-scan-title" onMouseDown={(event) => event.stopPropagation()}>
          <button type="button" className="icon-button modal__close" onClick={() => setDeepScanDialog(false)} aria-label="Закрыть"><X aria-hidden="true" /></button>
          <span className="modal__icon"><Radar aria-hidden="true" /></span><span className="eyebrow">Больше наблюдений</span><h2 id="deep-scan-title">Углублённая проверка</h2>
          <p>Маяк проверит больше локальных адресов и распространённых портов. Это может занять до минуты и заметнее для оборудования сети.</p>
          <div className="modal__facts"><span><Check aria-hidden="true" /> Только текущая локальная подсеть</span><span><Check aria-hidden="true" /> Без подбора паролей и эксплуатации</span><span><Check aria-hidden="true" /> Не выходит в интернет</span></div>
          <div className="modal__actions"><button type="button" className="secondary-button" onClick={() => setDeepScanDialog(false)}>Отмена</button><button type="button" className="primary-button" onClick={() => void startScan("deep", true)}>Начать</button></div>
        </section>
      </div>}
      <UpdateDialog update={updater.state} onInstall={() => void updater.install()} onClose={updater.dismissDialog} />
      {error && <div className="toast toast--error" role="alert"><AlertTriangle aria-hidden="true" /><span><strong>Не получилось выполнить действие</strong><small>{error}</small></span><button type="button" onClick={() => setError(undefined)} aria-label="Закрыть"><X aria-hidden="true" /></button></div>}
      {notice && <div className="toast toast--info" role="status"><Info aria-hidden="true" />{notice}</div>}
      {saved && <div className="toast toast--saved" role="status"><Check aria-hidden="true" />Сохранено</div>}
    </div>
  );
}
