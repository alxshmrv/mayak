export type PermissionState =
  | "notDetermined"
  | "allowed"
  | "denied"
  | "restricted"
  | "unknown";

export type Severity = "info" | "good" | "warning" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type VisibilityLevel = "limited" | "partial" | "good";
export type ScanMode = "safe" | "deep";
export type TrustState = "unknown" | "mine" | "known" | "ignored";
export type DeviceKind =
  | "router"
  | "computer"
  | "phone"
  | "tablet"
  | "printer"
  | "media"
  | "smartHome"
  | "camera"
  | "possibleCamera"
  | "networkEquipment"
  | "unknown";

export interface ChannelInfo {
  number: number;
  band: string;
  width: string;
}
export interface NetworkContext {
  connected: boolean;
  wifiAvailable: boolean;
  interfaceName?: string;
  ssid?: string;
  bssid?: string;
  security: string;
  phyMode?: string;
  channel?: ChannelInfo;
  rssi?: number;
  noise?: number;
  signalQuality?: number;
  transmitRateMbps?: number;
  countryCode?: string;
  ipv4?: string;
  ipv6: string[];
  subnet?: string;
  router?: string;
  dnsServers: string[];
  proxyEnabled: boolean;
  vpnActive: boolean;
  networkId: string;
}

export interface PermissionStatus {
  location: PermissionState;
  localNetwork: PermissionState;
}

export interface Finding {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation?: string;
  evidence: string[];
}

export interface Assessment {
  risk: Severity;
  visibility: VisibilityLevel;
  confidence: Confidence;
  summary: string;
  findings: Finding[];
}

export interface ServiceEvidence {
  protocol: string;
  name: string;
  serviceType?: string;
  port?: number;
  details: string[];
}

export interface ObservedDevice {
  identityKey: string;
  displayName: string;
  kind: DeviceKind;
  typeConfidence: Confidence;
  ipAddresses: string[];
  macAddress?: string;
  vendor?: string;
  hostnames: string[];
  openPorts: number[];
  services: ServiceEvidence[];
  evidence: string[];
  trustState: TrustState;
  isNew: boolean;
  firstSeen: string;
  lastSeen: string;
  responseTimeMs?: number;
  findings: Finding[];
}

export interface ScanCoverage {
  targetCount: number;
  responsiveCount: number;
  arpCount: number;
  mdnsCount: number;
  ssdpCount: number;
  onvifCount: number;
  methods: string[];
  limitedBySubnetSize: boolean;
  notes: string[];
}

export interface ScanReport {
  id: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  mode: ScanMode;
  network: NetworkContext;
  devices: ObservedDevice[];
  assessment: Assessment;
  coverage: ScanCoverage;
}

export interface HistoryEntry {
  id: string;
  completedAt: string;
  ssid?: string;
  security: string;
  risk: Severity;
  visibility: VisibilityLevel;
  deviceCount: number;
  newDeviceCount: number;
  mode: ScanMode;
}

export interface AppSettings {
  backgroundMonitoring: boolean;
  monitoringIntervalSeconds: number;
  defaultScanMode: ScanMode;
  notifyNewDevices: boolean;
  notifyNetworkChanges: boolean;
}

export interface AppSnapshot {
  network: NetworkContext;
  permissions: PermissionStatus;
  latestReport?: ScanReport;
  settings: AppSettings;
}

export interface ScanProgress {
  phase: string;
  title: string;
  detail: string;
  completed: number;
  total: number;
}
