import { createContext, useContext } from "react";
import type {
  Confidence, DeviceKind, PermissionState, Severity, TrustState, VisibilityLevel,
} from "./types";

export type Language = "ru" | "en";
export type LanguagePreference = "system" | Language;

/** Russian for a Russian locale, English for everything else. */
export function detectLanguage(locales: readonly string[] = typeof navigator === "undefined" ? [] : navigator.languages ?? [navigator.language]): Language {
  return locales[0]?.toLowerCase().startsWith("ru") ? "ru" : "en";
}

export function resolveLanguage(preference: LanguagePreference | undefined, systemLanguage: Language): Language {
  return !preference || preference === "system" ? systemLanguage : preference;
}

function russianPlural(count: number, one: string, few: string, many: string) {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return few;
  return many;
}

function decimal(value: number, separator: string) {
  return value.toFixed(1).replace(".", separator);
}

const ru = {
  locale: "ru-RU",
  appName: "Маяк",
  brandTagline: "локальная безопасность",
  loading: "Настраиваем Маяк…",
  close: "Закрыть",
  saved: "Сохранено",
  actionFailed: "Не получилось выполнить действие",
  notificationsDenied: "Система не разрешила уведомления. Их можно включить позже в настройках.",
  locationAllowed: "Имя текущей Wi-Fi-сети теперь доступно.",
  locationDenied: "Доступ отключён в системе. Откройте настройки, чтобы изменить его.",
  locationRequested: "Запрос отправлен. Если система не показала окно, нажмите «Открыть настройки».",
  severity: {
    good: "В порядке", info: "К сведению", warning: "Стоит проверить",
    high: "Высокий риск", critical: "Критический риск",
  } satisfies Record<Severity, string>,
  deviceKind: {
    router: "Маршрутизатор", computer: "Компьютер", phone: "Телефон", tablet: "Планшет",
    printer: "Принтер", media: "Медиаустройство", smartHome: "Умный дом", camera: "Камера",
    possibleCamera: "Возможная камера", networkEquipment: "Сетевое оборудование", unknown: "Неизвестно",
  } satisfies Record<DeviceKind, string>,
  trust: {
    unknown: "Не отмечено", mine: "Моё устройство", known: "Знакомое", ignored: "Игнорировать",
  } satisfies Record<TrustState, string>,
  visibility: {
    good: { label: "Хорошая", description: "Большинство доступных способов обнаружения сработали." },
    partial: { label: "Частичная", description: "Некоторые устройства могут быть скрыты настройками сети." },
    limited: { label: "Ограниченная", description: "Сеть существенно ограничивает обзор соседних устройств." },
  } satisfies Record<VisibilityLevel, { label: string; description: string }>,
  confidence: { high: "высокая", medium: "средняя", low: "низкая" } satisfies Record<Confidence, string>,
  permission: {
    allowed: "Разрешено", notDetermined: "Ещё не запрошено", denied: "Запрещено",
    restricted: "Ограничено системой", unknown: "Не определено",
  } satisfies Record<PermissionState, string>,
  security: { open: "Открытая сеть", unknown: "Не удалось определить" },
  unknownValue: "не определено",
  duration: (ms: number) => ms < 1_000 ? `${ms} мс` : `${decimal(ms / 1_000, ",")} с`,
  bytes: (value: number) => value < 1_024 ? `${value} Б`
    : value < 1_048_576 ? `${Math.round(value / 1_024)} КБ`
      : `${decimal(value / 1_048_576, ",")} МБ`,
  /** Native code reports bands and widths as "2.4 GHz" / "80 MHz". */
  radioUnits: (value: string) => value.replace(/(\d)\.(\d)/g, "$1,$2").replace("GHz", "ГГц").replace("MHz", "МГц"),
  radar: {
    label: "Радар обнаруженных устройств",
    title: "Радар обнаружения",
    subtitle: "Кольца показывают уверенность в типе, не расстояние",
    high: "тип подтверждён", medium: "тип вероятен", low: "тип не определён",
    more: (count: number) => `+${count} в списке`,
  },
  finding: { evidence: "Основание вывода" },
  facts: {
    title: "Все параметры сети",
    interface: "Интерфейс", ipv4: "IPv4", subnet: "Подсеть", gateway: "Шлюз", dns: "DNS",
    band: "Диапазон", channel: "Канал", mode: "Режим", phyRate: "Скорость PHY", rssiNoise: "RSSI / шум",
    country: "Страна", ipv6: "IPv6", proxy: "Прокси", vpn: "VPN",
    bssidHidden: "Скрыт системой", mbps: "Мбит/с", proxyOn: "Включён", vpnOn: "Активен", notDetected: "Не обнаружен",
    methods: "Способы обнаружения", coverage: "Охват",
    coverageSummary: (checked: number, responded: number) => `Проверено ${checked} ${russianPlural(checked, "адрес", "адреса", "адресов")} · ответили ${responded}`,
  },
  overview: {
    eyebrow: "Текущая Wi-Fi-сеть",
    unnamedNetwork: "Сеть без имени",
    verdictNote: "Маяк разделяет риск сети и полноту обзора: невидимое устройство не означает, что его нет.",
    signal: "сигнал", wifiSecurity: "защита Wi-Fi",
    summaryLabel: "Итоги проверки",
    devicesVisible: (count: number) => russianPlural(count, "устройство видно", "устройства видно", "устройств видно"),
    unreviewedNew: "новых без отметки",
    networkVisibility: "видимость сети",
    none: "Нет", needsReview: "нужно проверить", cameraSigns: "признаков камер",
    resultEyebrow: "Разбор результата", resultTitle: "Что важно знать",
    confidence: (value: string) => `Уверенность: ${value}`,
    footnote: (time: string, duration: string, deep: boolean) => `Проверка завершена в ${time} за ${duration} · режим ${deep ? "углублённый" : "безопасный"}`,
  },
  device: {
    detailsLabel: (name: string) => `Сведения: ${name}`,
    cameraConfirmed: "Обнаружены признаки IP-камеры",
    cameraPossible: "Есть признаки, совместимые с камерой",
    cameraNote: "Это техническая гипотеза, а не доказательство скрытого наблюдения. Сверьте производителя, имя и сервисы.",
    trustTitle: "Как вы знаете устройство",
    ipAddresses: "IP-адреса", mac: "MAC-адрес", vendor: "Производитель", names: "Имена",
    openPorts: "Открытые порты", firstSeen: "Впервые замечено", lastSeen: "Последний ответ", typeConfidence: "Уверенность в типе",
    macHidden: "Не виден", vendorUnknown: "Не определён", namesNone: "Не объявлены", portsNone: "Не найдены",
    services: "Объявленные сервисы", port: (port: number) => `порт ${port}`,
    whyVisible: "Почему Маяк видит это устройство",
  },
  devices: {
    eyebrow: "Текущая сеть", title: "Видимые устройства",
    description: "Маяк показывает наблюдаемые признаки и отдельно отмечает уровень уверенности.",
    search: "Найти устройство", searchPlaceholder: "Имя, IP, MAC или производитель", clearSearch: "Очистить поиск",
    filterLabel: "Фильтр устройств",
    filters: { all: "Все", new: "Новые", attention: "Проверить", known: "Знакомые" },
    columns: ["Устройство", "Адрес", "Наблюдения", "Статус"],
    macHidden: "MAC не виден",
    ports: (ports: string) => `Порты ${ports}`,
    noPorts: "Открытые порты не найдены",
    services: (count: number) => `${count} ${russianPlural(count, "сервис", "сервиса", "сервисов")}`,
    typeConfidence: (value: string) => `Тип: уверенность ${value}`,
    review: "Проверить", new: "Новое", observed: "Наблюдается",
    emptyTitle: "Ничего не найдено", emptyDescription: "Измените запрос или выберите другой фильтр.",
  },
  history: {
    eyebrow: "Только на этом компьютере", title: "История наблюдений",
    description: "Сравнивайте знакомые сети и замечайте изменения точки доступа или состава устройств.",
    current: "текущая",
    devices: (count: number) => russianPlural(count, "устройство", "устройства", "устройств"),
    newDevices: (count: number) => russianPlural(count, "новое", "новых", "новых"),
    visibility: "видимость",
    emptyTitle: "История пока пуста", emptyDescription: "Первая запись появится после завершённой проверки.",
    privacyTitle: "История остаётся локальной",
    privacyDescription: "Маяк не отправляет имена сетей, адреса и сведения об устройствах в облако.",
  },
  update: {
    checking: "Проверяем GitHub Releases…",
    available: (version: string) => `Доступна версия ${version}`,
    downloaded: (size: string) => `Загружено ${size}`,
    installing: "Проверяем подпись и устанавливаем…",
    restarting: "Перезапускаем Маяк…",
    current: "Установлена последняя версия",
    failed: "Не удалось проверить или установить обновление. Проверьте интернет и повторите попытку.",
    schedule: "Проверяем при запуске и затем каждые 6 часов",
    retryInstall: "Повторить установку", view: "Посмотреть", inProgress: "Выполняется…",
    checkingShort: "Проверяем…", check: "Проверить",
    title: "Обновления", description: "Только подписанные пакеты из официального GitHub Releases.",
    version: "Версия Маяка", detectingVersion: "Определяем…",
    lastChecked: (time: string) => `Последняя проверка: ${time}`,
    dialogEyebrow: "Подписанное обновление",
    dialogTitle: (version: string) => `Маяк ${version}`,
    dialogBody: (current: string) => `Установлена версия ${current}. Маяк проверит подпись пакета до любых изменений и перезапустится только после установки.`,
    notes: "Что изменилось",
    factSigned: "Пакет подписан ключом проекта",
    factHttps: "Загрузка только по HTTPS из GitHub Releases",
    factRestart: "Перезапуск после успешной установки",
    downloading: (percentage?: number) => `Загружаем${percentage === undefined ? "…" : `: ${percentage}%`}`,
    installingSigned: "Устанавливаем подписанное обновление…",
    progress: (done: string, total: string) => `${done} из ${total}`,
    later: "Позже", updating: "Обновляем…", retry: "Повторить", installAndRestart: "Установить и перезапустить",
  },
  settings: {
    eyebrow: "Поведение Маяка", title: "Настройки",
    description: "Фоновая проверка работает локально и только в текущей Wi-Fi-сети.",
    monitoringTitle: "Наблюдение", monitoringDescription: "Замечает новые устройства без постоянно открытого окна.",
    background: "Фоновое наблюдение", backgroundHint: "Проверять сеть через заданный интервал",
    interval: "Интервал", intervalHint: "Чем чаще, тем быстрее Маяк заметит изменение",
    intervals: { 60: "Каждую минуту", 300: "Каждые 5 минут", 900: "Каждые 15 минут", 1800: "Каждые 30 минут" } as Record<number, string>,
    defaultMode: "Обычный режим проверки", defaultModeHint: "Углублённый режим проверяет больше адресов и портов",
    modeSafe: "Безопасный", modeDeep: "Углублённый",
    alertsTitle: "Сигналы", alertsDescription: "Только значимые изменения — без постоянного шума.",
    newDevice: "Новое устройство", newDeviceHint: "Сообщать о новом соседе в знакомой сети",
    networkChanged: "Изменилась сеть", networkChangedHint: "Новый BSSID, шлюз или тип защиты",
    languageTitle: "Язык", languageDescription: "Язык интерфейса, уведомлений и меню в строке состояния.",
    language: "Язык интерфейса",
    languageHint: "Уже собранные результаты останутся на прежнем языке до следующей проверки",
    languageSystem: "Как в системе",
    accessTitle: "Системный доступ", accessDescription: "Геопозиция раскрывает только SSID/BSSID; сканирование работает без неё.",
    location: "Службы геолокации", localNetwork: "Локальная сеть",
    allow: "Разрешить", openSettings: "Открыть настройки", allowed: "Разрешено",
  },
  location: {
    label: "Имя Wi-Fi скрыто системой",
    requested: "Запрос отправлен системе",
    hidden: "Имя Wi-Fi пока скрыто системой",
    requestedHint: "Если системное окно не появилось, разрешите геопозицию в настройках. Сканирование уже работает.",
    hiddenHint: "Проверка устройств уже работает. Доступ нужен только для SSID и BSSID; координаты Маяк не получает.",
    show: "Показать имя сети",
  },
  disconnected: {
    eyebrow: "Нет активной Wi-Fi-сети", title: "Подключитесь к сети",
    description: "Как только Wi-Fi появится, Маяк прочитает его параметры и сможет безопасно проверить локальное окружение.",
    retry: "Проверить ещё раз",
  },
  mascot: {
    listening: "Слушаю сеть…", done: "Готово! Я всё разложил.", concerned: "Тут есть что проверить.",
    newNeighbors: (count: number) => `${count} ${russianPlural(count, "новый сосед", "новых соседа", "новых соседей")}`,
    watching: "Я присматриваю за сетью.", ready: "Готов проверить сеть.",
  },
  nav: { label: "Разделы", overview: "Обзор", devices: "Устройства", history: "История", settings: "Настройки" },
  sidebar: { online: "Сейчас в сети", offline: "Нет Wi-Fi", nameHidden: "Имя скрыто системой", notConnected: "Не подключено" },
  topbar: {
    scanning: "Проверяем сеть",
    checkedAt: (time: string) => `Проверено ${time}`,
    neverChecked: "Сеть ещё не проверялась",
    scan: "Проверить сеть", scanningShort: "Проверяем…", deepScan: "Углублённая проверка",
  },
  firstRun: {
    eyebrow: "Всё готово", title: "Познакомимся с этой сетью?",
    description: "Первая безопасная проверка соберёт параметры Wi-Fi и доступные признаки соседних устройств — даже если имя сети скрыто системой.",
    start: "Начать проверку",
  },
  scanStart: {
    safe: "Начинаем проверку", deep: "Начинаем углублённую проверку",
    detail: "Готовим безопасные локальные запросы",
  },
  deepScan: {
    eyebrow: "Больше наблюдений", title: "Углублённая проверка",
    description: "Маяк проверит больше локальных адресов и распространённых портов. Это может занять до минуты и заметнее для оборудования сети.",
    factSubnet: "Только текущая локальная подсеть", factNoExploits: "Без подбора паролей и эксплуатации", factOffline: "Не выходит в интернет",
    cancel: "Отмена", start: "Начать",
  },
};

export type Messages = typeof ru;

const en: Messages = {
  locale: "en-US",
  appName: "Mayak",
  brandTagline: "local network safety",
  loading: "Setting up Mayak…",
  close: "Close",
  saved: "Saved",
  actionFailed: "Something went wrong",
  notificationsDenied: "The system did not allow notifications. You can turn them on later in settings.",
  locationAllowed: "The current Wi-Fi network name is now available.",
  locationDenied: "Access is turned off in the system. Open settings to change it.",
  locationRequested: "Request sent. If the system did not show a prompt, click “Open settings”.",
  severity: {
    good: "All good", info: "For your information", warning: "Worth checking",
    high: "High risk", critical: "Critical risk",
  },
  deviceKind: {
    router: "Router", computer: "Computer", phone: "Phone", tablet: "Tablet",
    printer: "Printer", media: "Media device", smartHome: "Smart home", camera: "Camera",
    possibleCamera: "Possible camera", networkEquipment: "Network equipment", unknown: "Unknown",
  },
  trust: {
    unknown: "Not marked", mine: "My device", known: "Known", ignored: "Ignore",
  },
  visibility: {
    good: { label: "Good", description: "Most available discovery methods worked." },
    partial: { label: "Partial", description: "Some devices may be hidden by network settings." },
    limited: { label: "Limited", description: "The network significantly limits the view of nearby devices." },
  },
  confidence: { high: "high", medium: "medium", low: "low" },
  permission: {
    allowed: "Allowed", notDetermined: "Not requested yet", denied: "Denied",
    restricted: "Restricted by the system", unknown: "Unknown",
  },
  security: { open: "Open network", unknown: "Could not determine" },
  unknownValue: "unknown",
  duration: (ms: number) => ms < 1_000 ? `${ms} ms` : `${decimal(ms / 1_000, ".")} s`,
  bytes: (value: number) => value < 1_024 ? `${value} B`
    : value < 1_048_576 ? `${Math.round(value / 1_024)} KB`
      : `${decimal(value / 1_048_576, ".")} MB`,
  radioUnits: (value: string) => value,
  radar: {
    label: "Radar of discovered devices",
    title: "Discovery radar",
    subtitle: "Rings show confidence in the device type, not distance",
    high: "type confirmed", medium: "type likely", low: "type unknown",
    more: (count: number) => `+${count} more in the list`,
  },
  finding: { evidence: "Evidence" },
  facts: {
    title: "All network details",
    interface: "Interface", ipv4: "IPv4", subnet: "Subnet", gateway: "Gateway", dns: "DNS",
    band: "Band", channel: "Channel", mode: "Mode", phyRate: "PHY rate", rssiNoise: "RSSI / noise",
    country: "Country", ipv6: "IPv6", proxy: "Proxy", vpn: "VPN",
    bssidHidden: "Hidden by the system", mbps: "Mbps", proxyOn: "On", vpnOn: "Active", notDetected: "Not detected",
    methods: "Discovery methods", coverage: "Coverage",
    coverageSummary: (checked: number, responded: number) => `${checked} ${checked === 1 ? "address" : "addresses"} checked · ${responded} responded`,
  },
  overview: {
    eyebrow: "Current Wi-Fi network",
    unnamedNetwork: "Unnamed network",
    verdictNote: "Mayak keeps network risk separate from how much it could see: an invisible device does not mean there is none.",
    signal: "signal", wifiSecurity: "Wi-Fi security",
    summaryLabel: "Check summary",
    devicesVisible: (count: number) => count === 1 ? "device visible" : "devices visible",
    unreviewedNew: "new, not marked",
    networkVisibility: "network visibility",
    none: "None", needsReview: "need a closer look", cameraSigns: "camera signs",
    resultEyebrow: "Result breakdown", resultTitle: "What to know",
    confidence: (value: string) => `Confidence: ${value}`,
    footnote: (time: string, duration: string, deep: boolean) => `Check finished at ${time} in ${duration} · ${deep ? "deep" : "safe"} mode`,
  },
  device: {
    detailsLabel: (name: string) => `Details: ${name}`,
    cameraConfirmed: "Signs of an IP camera detected",
    cameraPossible: "Signs consistent with a camera",
    cameraNote: "This is a technical hypothesis, not proof of hidden surveillance. Compare the vendor, name, and services.",
    trustTitle: "How do you know this device?",
    ipAddresses: "IP addresses", mac: "MAC address", vendor: "Vendor", names: "Names",
    openPorts: "Open ports", firstSeen: "First seen", lastSeen: "Last response", typeConfidence: "Type confidence",
    macHidden: "Not visible", vendorUnknown: "Unknown", namesNone: "Not announced", portsNone: "None found",
    services: "Announced services", port: (port: number) => `port ${port}`,
    whyVisible: "Why Mayak sees this device",
  },
  devices: {
    eyebrow: "Current network", title: "Visible devices",
    description: "Mayak shows what it observed and marks its confidence separately.",
    search: "Find a device", searchPlaceholder: "Name, IP, MAC, or vendor", clearSearch: "Clear search",
    filterLabel: "Device filter",
    filters: { all: "All", new: "New", attention: "Review", known: "Known" },
    columns: ["Device", "Address", "Observations", "Status"],
    macHidden: "MAC not visible",
    ports: (ports: string) => `Ports ${ports}`,
    noPorts: "No open ports found",
    services: (count: number) => `${count} ${count === 1 ? "service" : "services"}`,
    typeConfidence: (value: string) => `Type: ${value} confidence`,
    review: "Review", new: "New", observed: "Observed",
    emptyTitle: "Nothing found", emptyDescription: "Change your search or pick another filter.",
  },
  history: {
    eyebrow: "Only on this computer", title: "Observation history",
    description: "Compare familiar networks and notice changes in the access point or the set of devices.",
    current: "current",
    devices: (count: number) => count === 1 ? "device" : "devices",
    newDevices: () => "new",
    visibility: "visibility",
    emptyTitle: "No history yet", emptyDescription: "The first entry appears after a completed check.",
    privacyTitle: "History stays local",
    privacyDescription: "Mayak never sends network names, addresses, or device details to the cloud.",
  },
  update: {
    checking: "Checking GitHub Releases…",
    available: (version: string) => `Version ${version} is available`,
    downloaded: (size: string) => `Downloaded ${size}`,
    installing: "Verifying the signature and installing…",
    restarting: "Restarting Mayak…",
    current: "You have the latest version",
    failed: "Couldn't check for or install the update. Check your internet connection and try again.",
    schedule: "Checked at launch and then every 6 hours",
    retryInstall: "Retry installation", view: "View", inProgress: "In progress…",
    checkingShort: "Checking…", check: "Check",
    title: "Updates", description: "Only signed packages from the official GitHub Releases.",
    version: "Mayak version", detectingVersion: "Detecting…",
    lastChecked: (time: string) => `Last checked: ${time}`,
    dialogEyebrow: "Signed update",
    dialogTitle: (version: string) => `Mayak ${version}`,
    dialogBody: (current: string) => `You have version ${current}. Mayak verifies the package signature before changing anything and restarts only after a successful install.`,
    notes: "What's new",
    factSigned: "Package signed with the project key",
    factHttps: "Downloaded only over HTTPS from GitHub Releases",
    factRestart: "Restarts after a successful install",
    downloading: (percentage?: number) => `Downloading${percentage === undefined ? "…" : `: ${percentage}%`}`,
    installingSigned: "Installing the signed update…",
    progress: (done: string, total: string) => `${done} of ${total}`,
    later: "Later", updating: "Updating…", retry: "Retry", installAndRestart: "Install and restart",
  },
  settings: {
    eyebrow: "How Mayak behaves", title: "Settings",
    description: "Background checks run locally and only on the current Wi-Fi network.",
    monitoringTitle: "Monitoring", monitoringDescription: "Notices new devices without keeping the window open.",
    background: "Background monitoring", backgroundHint: "Check the network at a set interval",
    interval: "Interval", intervalHint: "The more often, the sooner Mayak notices a change",
    intervals: { 60: "Every minute", 300: "Every 5 minutes", 900: "Every 15 minutes", 1800: "Every 30 minutes" },
    defaultMode: "Default check mode", defaultModeHint: "Deep mode checks more addresses and ports",
    modeSafe: "Safe", modeDeep: "Deep",
    alertsTitle: "Alerts", alertsDescription: "Only meaningful changes — no constant noise.",
    newDevice: "New device", newDeviceHint: "Tell me about a new neighbor on a familiar network",
    networkChanged: "Network changed", networkChangedHint: "New BSSID, gateway, or security type",
    languageTitle: "Language", languageDescription: "Language of the interface, notifications, and the menu bar menu.",
    language: "Interface language",
    languageHint: "Results already collected stay in their original language until the next check",
    languageSystem: "System default",
    accessTitle: "System access", accessDescription: "Location only reveals the SSID/BSSID; scanning works without it.",
    location: "Location Services", localNetwork: "Local network",
    allow: "Allow", openSettings: "Open settings", allowed: "Allowed",
  },
  location: {
    label: "Wi-Fi name hidden by the system",
    requested: "Request sent to the system",
    hidden: "The Wi-Fi name is hidden by the system",
    requestedHint: "If no system prompt appeared, allow location access in settings. Scanning already works.",
    hiddenHint: "Device checks already work. Access is needed only for the SSID and BSSID; Mayak never receives coordinates.",
    show: "Show network name",
  },
  disconnected: {
    eyebrow: "No active Wi-Fi network", title: "Connect to a network",
    description: "As soon as Wi-Fi is available, Mayak will read its settings and can safely check the local surroundings.",
    retry: "Check again",
  },
  mascot: {
    listening: "Listening to the network…", done: "Done! I've sorted it all out.", concerned: "There's something to check here.",
    newNeighbors: (count: number) => `${count} new ${count === 1 ? "neighbor" : "neighbors"}`,
    watching: "I'm keeping an eye on the network.", ready: "Ready to check the network.",
  },
  nav: { label: "Sections", overview: "Overview", devices: "Devices", history: "History", settings: "Settings" },
  sidebar: { online: "Connected", offline: "No Wi-Fi", nameHidden: "Name hidden by the system", notConnected: "Not connected" },
  topbar: {
    scanning: "Checking the network",
    checkedAt: (time: string) => `Checked at ${time}`,
    neverChecked: "Network not checked yet",
    scan: "Check network", scanningShort: "Checking…", deepScan: "Deep check",
  },
  firstRun: {
    eyebrow: "All set", title: "Shall we get to know this network?",
    description: "The first safe check collects Wi-Fi settings and the available signs of nearby devices — even if the network name is hidden by the system.",
    start: "Start check",
  },
  scanStart: {
    safe: "Starting the check", deep: "Starting the deep check",
    detail: "Preparing safe local requests",
  },
  deepScan: {
    eyebrow: "More observations", title: "Deep check",
    description: "Mayak will check more local addresses and common ports. This can take up to a minute and is more noticeable to network equipment.",
    factSubnet: "Only the current local subnet", factNoExploits: "No password guessing or exploitation", factOffline: "Never goes to the internet",
    cancel: "Cancel", start: "Start",
  },
};

export const messages: Record<Language, Messages> = { ru, en };

export const I18nContext = createContext<Messages>(ru);

export function useI18n() {
  return useContext(I18nContext);
}
