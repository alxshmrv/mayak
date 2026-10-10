import type { Language } from "./i18n";
import type {
  AppSnapshot,
  HistoryEntry,
  ObservedDevice,
  ScanProgress,
  ScanReport,
} from "./types";

const now = new Date();
const iso = now.toISOString();

/** Preview copy mirrors what the native side generates in each language. */
const copy = {
  ru: {
    probed: "Устройство ответило на безопасную сетевую проверку",
    gateway: "Шлюз сети",
    gatewayEvidence: "Шлюз текущей Wi-Fi-сети",
    arpEvidence: "MAC-адрес найден в таблице соседей (ARP)",
    thisComputer: "Этот компьютер",
    localEvidence: "Локальный интерфейс этого компьютера",
    guestPhone: "iPhone гостя",
    unknownDevice: "Неизвестное устройство · 10.42.18.116",
    summary: "Есть моменты, которые стоит проверить.",
    modernTitle: "Современная защита радиообмена",
    modernDescription: "Сеть использует WPA2/WPA3. Это защищает соединение с точкой доступа, но не делает локальную сеть доверенной.",
    apiEvidence: "Системный Wi-Fi API: wpa2-wpa3-transition",
    newTitle: "Три новых устройства",
    newDescription: "Они впервые появились в локальной истории Маяка. Для гостиничной сети это ожидаемо.",
    newRecommendation: "Проверяйте протоколы и производителя, а не только факт появления.",
    visibilityTitle: "Видимость может быть неполной",
    visibilityDescription: "Client isolation и другие VLAN способны скрыть часть устройств.",
    visibilityEvidence: ["Ответили 6 из 253 адресов", "Bonjour: 2 сервиса"],
    note: "Молчащие устройства, другие VLAN и устройства за изоляцией могут быть невидимы.",
    phases: [
      ["Читаем параметры Wi-Fi", "Системный Wi-Fi API, маршруты и DNS"],
      ["Ищем отвечающие устройства", "Проверено 128 из 253 адресов"],
      ["Сверяем соседей", "ARP, Bonjour, SSDP и ONVIF"],
    ],
  },
  en: {
    probed: "The device responded to a safe network check",
    gateway: "Network gateway",
    gatewayEvidence: "Gateway of the current Wi-Fi network",
    arpEvidence: "MAC address found in the neighbor table (ARP)",
    thisComputer: "This computer",
    localEvidence: "This computer's local interface",
    guestPhone: "Guest iPhone",
    unknownDevice: "Unknown device · 10.42.18.116",
    summary: "A few things are worth checking.",
    modernTitle: "Modern wireless security",
    modernDescription: "The network uses WPA2/WPA3. This protects the link to the access point but does not make the local network trustworthy.",
    apiEvidence: "System Wi-Fi API: wpa2-wpa3-transition",
    newTitle: "Three new devices",
    newDescription: "They appeared in Mayak's local history for the first time. On a hotel network this is expected.",
    newRecommendation: "Look at protocols and vendors, not just the fact that a device appeared.",
    visibilityTitle: "Visibility may be incomplete",
    visibilityDescription: "Client isolation and other VLANs can hide some devices.",
    visibilityEvidence: ["6 of 253 addresses responded", "Bonjour: 2 services"],
    note: "Silent devices, other VLANs, and isolated devices may be invisible.",
    phases: [
      ["Reading Wi-Fi settings", "System Wi-Fi API, routes, and DNS"],
      ["Looking for responding devices", "Checked 128 of 253 addresses"],
      ["Cross-checking neighbors", "ARP, Bonjour, SSDP, and ONVIF"],
    ],
  },
} satisfies Record<Language, unknown>;

export function mockScanPhases(language: Language): ScanProgress[] {
  const [network, tcp, neighbors] = copy[language].phases;
  return [
    { phase: "network", title: network[0], detail: network[1], completed: 0, total: 1 },
    { phase: "tcp", title: tcp[0], detail: tcp[1], completed: 128, total: 253 },
    { phase: "neighbors", title: neighbors[0], detail: neighbors[1], completed: 253, total: 253 },
  ];
}

export function createMockReport(language: Language): ScanReport {
  const t = copy[language];
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
    evidence: [t.probed],
    trustState: "unknown",
    isNew: false,
    firstSeen: iso,
    lastSeen: iso,
    findings: [],
    ...partial,
  });

  return {
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
      localMacAddress: "02:00:00:00:00:02",
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
      device("mac:router", t.gateway, "router", "10.42.18.1", {
        macAddress: "02:00:00:00:00:01",
        vendor: "Ubiquiti",
        openPorts: [80, 443],
        evidence: [t.gatewayEvidence, t.arpEvidence],
      }),
      device("local:computer", t.thisComputer, "computer", "10.42.18.37", {
        trustState: "mine",
        macAddress: "02:00:00:00:00:02",
        evidence: [t.localEvidence],
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
      device("mac:phone", t.guestPhone, "phone", "10.42.18.74", {
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
        t.unknownDevice,
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
      summary: t.summary,
      findings: [
        {
          id: "wifi-modern",
          category: "network",
          severity: "good",
          title: t.modernTitle,
          description: t.modernDescription,
          evidence: [t.apiEvidence],
        },
        {
          id: "new-devices",
          category: "device",
          severity: "warning",
          title: t.newTitle,
          description: t.newDescription,
          recommendation: t.newRecommendation,
          evidence: [t.guestPhone, "workstation-23", "10.42.18.116"],
        },
        {
          id: "visibility",
          category: "coverage",
          severity: "info",
          title: t.visibilityTitle,
          description: t.visibilityDescription,
          evidence: t.visibilityEvidence,
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
      notes: [t.note],
    },
  };
}

export function createMockSnapshot(language: Language): AppSnapshot {
  const report = createMockReport(language);
  return {
    network: report.network,
    permissions: {
      location: "notDetermined",
      localNetwork: "allowed",
    },
    latestReport: report,
    settings: {
      backgroundMonitoring: true,
      monitoringIntervalSeconds: 300,
      defaultScanMode: "safe",
      notifyNewDevices: true,
      notifyNetworkChanges: true,
      language: "system",
    },
    systemLanguage: language,
  };
}

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
