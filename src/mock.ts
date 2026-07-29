import type {
  AppSnapshot,
  HistoryEntry,
  ObservedDevice,
  ScanReport,
} from "./types";

const now = new Date();
const iso = now.toISOString();

const device = (
  identityKey: string,
  displayName: string,
  kind: ObservedDevice["kind"],
  ip: string,
  partial: Partial<ObservedDevice> = {},
): ObservedDevice => ({
  identityKey,
  displayName,
  kind,
  typeConfidence: "high",
  ipAddresses: [ip],
  hostnames: [],
  openPorts: [],
  services: [],
  evidence: ["Устройство ответило на безопасную сетевую проверку"],
  trustState: "unknown",
  isNew: false,
  firstSeen: iso,
  lastSeen: iso,
  findings: [],
  ...partial,
});

export const mockReport: ScanReport = {
  id: "preview-report",
  startedAt: new Date(now.getTime() - 4_800).toISOString(),
  completedAt: iso,
  durationMs: 4_800,
  mode: "safe",
  network: {
    connected: true,
    wifiAvailable: true,
    interfaceName: "en0",
    ssid: "Hotel Aurora",
    bssid: "02:00:00:00:00:01",
    security: "wpa2-wpa3-transition",
    phyMode: "Wi-Fi 6",
    channel: { number: 44, band: "5 GHz", width: "80 MHz" },
    rssi: -57,
    noise: -92,
    signalQuality: 86,
    transmitRateMbps: 780,
    countryCode: "RU",
    ipv4: "10.42.18.37",
    ipv6: ["fe80::18a4:11ff:fe22:178a"],
    subnet: "10.42.18.0/24",
    router: "10.42.18.1",
    dnsServers: ["10.42.18.1", "1.1.1.1"],
    proxyEnabled: false,
    vpnActive: true,
    networkId: "preview-network",
  },
  devices: [
    device("mac:router", "Шлюз сети", "router", "10.42.18.1", {
      macAddress: "02:00:00:00:00:01",
      vendor: "Ubiquiti",
      openPorts: [80, 443],
      evidence: ["Шлюз текущей Wi-Fi-сети", "MAC-адрес найден в ARP-таблице"],
    }),
    device("local:mac", "Этот Mac", "computer", "10.42.18.37", {
      trustState: "mine",
      macAddress: "02:00:00:00:00:02",
      evidence: ["Локальный интерфейс этого Mac"],
    }),
    device("mac:tv", "Aurora Lounge TV", "media", "10.42.18.52", {
      vendor: "Samsung",
      hostnames: ["aurora-tv.local."],
      openPorts: [8008, 8009],
      services: [
        {
          protocol: "mdns",
          name: "Aurora Lounge TV",
          serviceType: "_googlecast._tcp.local.",
          port: 8009,
          details: [],
        },
      ],
      evidence: ["Bonjour: _googlecast._tcp.local."],
    }),
    device("mac:printer", "Reception Printer", "printer", "10.42.18.61", {
      vendor: "HP",
      openPorts: [631, 9100],
      services: [
        {
          protocol: "mdns",
          name: "Reception Printer",
          serviceType: "_ipp._tcp.local.",
          port: 631,
          details: [],
        },
      ],
    }),
    device("mac:phone", "iPhone гостя", "phone", "10.42.18.74", {
      typeConfidence: "medium",
      vendor: "Apple",
      isNew: true,
    }),
    device("mac:laptop", "workstation-23", "computer", "10.42.18.91", {
      typeConfidence: "medium",
      openPorts: [22],
      isNew: true,
    }),
    device(
      "observed:unknown",
      "Неизвестное устройство · 10.42.18.116",
      "unknown",
      "10.42.18.116",
      {
        typeConfidence: "low",
        openPorts: [80],
        isNew: true,
      },
    ),
  ],
  assessment: {
    risk: "warning",
    visibility: "partial",
    confidence: "high",
    summary: "Есть моменты, которые стоит проверить.",
    findings: [
      {
        id: "wifi-modern",
        category: "network",
        severity: "good",
        title: "Современная защита радиообмена",
        description:
          "Сеть использует WPA2/WPA3. Это защищает соединение с точкой доступа, но не делает локальную сеть доверенной.",
        evidence: ["CoreWLAN: wpa2-wpa3-transition"],
      },
      {
        id: "new-devices",
        category: "device",
        severity: "warning",
        title: "Три новых устройства",
        description:
          "Они впервые появились в локальной истории Маяка. Для гостиничной сети это ожидаемо.",
        recommendation:
          "Проверяйте протоколы и производителя, а не только факт появления.",
        evidence: ["iPhone гостя", "workstation-23", "10.42.18.116"],
      },
      {
        id: "visibility",
        category: "coverage",
        severity: "info",
        title: "Видимость может быть неполной",
        description:
          "Client isolation и другие VLAN способны скрыть часть устройств.",
        evidence: ["Ответили 6 из 253 адресов", "Bonjour: 2 сервиса"],
      },
    ],
  },
  coverage: {
    targetCount: 253,
    responsiveCount: 6,
    arpCount: 5,
    mdnsCount: 2,
    ssdpCount: 1,
    onvifCount: 0,
    methods: [
      "TCP connect",
      "ARP cache",
      "Bonjour / mDNS",
      "SSDP",
      "ONVIF / WS-Discovery",
    ],
    limitedBySubnetSize: false,
    notes: [
      "Молчащие устройства, другие VLAN и устройства за изоляцией могут быть невидимы.",
    ],
  },
};

export const mockSnapshot: AppSnapshot = {
  network: mockReport.network,
  permissions: {
    location: "notDetermined",
    localNetwork: "allowed",
  },
  latestReport: mockReport,
  settings: {
    backgroundMonitoring: true,
    monitoringIntervalSeconds: 300,
    defaultScanMode: "safe",
    notifyNewDevices: true,
    notifyNetworkChanges: true,
  },
};

export const mockHistory: HistoryEntry[] = [
  {
    id: "preview-report",
    completedAt: iso,
    ssid: "Hotel Aurora",
    security: "wpa2-wpa3-transition",
    risk: "warning",
    visibility: "partial",
    deviceCount: 7,
    newDeviceCount: 3,
    mode: "safe",
  },
  {
    id: "home-report",
    completedAt: new Date(now.getTime() - 86_400_000).toISOString(),
    ssid: "Home 5G",
    security: "wpa3-personal",
    risk: "info",
    visibility: "good",
    deviceCount: 11,
    newDeviceCount: 0,
    mode: "deep",
  },
  {
    id: "airport-report",
    completedAt: new Date(now.getTime() - 259_200_000).toISOString(),
    ssid: "Airport Free",
    security: "open",
    risk: "critical",
    visibility: "limited",
    deviceCount: 2,
    newDeviceCount: 1,
    mode: "safe",
  },
];
