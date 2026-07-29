use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};

use crate::domain::{AppSettings, HistoryEntry, ObservedDevice, ScanReport, TrustState};
use crate::error::{AppError, AppResult};
use crate::network::stable_network_id;

pub struct Storage {
    connection: Mutex<Connection>,
}

impl Storage {
    pub fn open(path: &Path) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }

        let connection = Connection::open(path)?;
        let storage = Self {
            connection: Mutex::new(connection),
        };
        storage.migrate()?;
        Ok(storage)
    }

    #[cfg(test)]
    pub fn in_memory() -> AppResult<Self> {
        let storage = Self {
            connection: Mutex::new(Connection::open_in_memory()?),
        };
        storage.migrate()?;
        Ok(storage)
    }

    fn migrate(&self) -> AppResult<()> {
        let mut connection = self.connection.lock();
        connection.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                completed_at TEXT NOT NULL,
                network_id TEXT NOT NULL,
                ssid TEXT,
                payload_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scans_completed_at
                ON scans(completed_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scans_network_id
                ON scans(network_id, completed_at DESC);

            CREATE TABLE IF NOT EXISTS observed_devices (
                network_id TEXT NOT NULL,
                identity_key TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY(network_id, identity_key)
            );

            CREATE TABLE IF NOT EXISTS device_preferences (
                network_id TEXT NOT NULL,
                identity_key TEXT NOT NULL,
                trust_state TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(network_id, identity_key)
            );
            ",
        )?;

        let has_network_id = {
            let mut statement = connection.prepare("PRAGMA table_info(observed_devices)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "network_id" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_network_id {
            connection.execute_batch(
                "
                DROP TABLE observed_devices;
                CREATE TABLE observed_devices (
                    network_id TEXT NOT NULL,
                    identity_key TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY(network_id, identity_key)
                );
                ",
            )?;
        }

        let preferences_have_network_id = {
            let mut statement = connection.prepare("PRAGMA table_info(device_preferences)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "network_id" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !preferences_have_network_id {
            connection.execute_batch(
                "
                DROP TABLE device_preferences;
                CREATE TABLE device_preferences (
                    network_id TEXT NOT NULL,
                    identity_key TEXT NOT NULL,
                    trust_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(network_id, identity_key)
                );
                ",
            )?;
        }
        migrate_network_ids(&mut connection)?;
        Ok(())
    }

    pub fn settings(&self) -> AppResult<AppSettings> {
        let connection = self.connection.lock();
        let value = connection
            .query_row(
                "SELECT value_json FROM settings WHERE key = 'app'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        value.map_or_else(
            || Ok(AppSettings::default()),
            |json| serde_json::from_str(&json).map_err(AppError::from),
        )
    }

    pub fn save_settings(&self, settings: &AppSettings) -> AppResult<()> {
        let json = serde_json::to_string(settings)?;
        self.connection.lock().execute(
            "
            INSERT INTO settings(key, value_json, updated_at)
            VALUES ('app', ?1, ?2)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at
            ",
            params![json, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn latest_report(&self) -> AppResult<Option<ScanReport>> {
        let mut report = self.load_optional_report(
            "SELECT payload_json FROM scans ORDER BY completed_at DESC LIMIT 1",
            [],
        )?;
        if let Some(report) = report.as_mut() {
            self.enrich_device_history(&report.network.network_id, &mut report.devices)?;
        }
        Ok(report)
    }

    pub fn latest_report_for_ssid(&self, ssid: Option<&str>) -> AppResult<Option<ScanReport>> {
        let Some(ssid) = ssid else {
            return Ok(None);
        };
        self.load_optional_report(
            "
            SELECT payload_json
            FROM scans
            WHERE ssid = ?1
            ORDER BY completed_at DESC
            LIMIT 1
            ",
            [ssid],
        )
    }

    fn load_optional_report<P>(&self, query: &str, params: P) -> AppResult<Option<ScanReport>>
    where
        P: rusqlite::Params,
    {
        let connection = self.connection.lock();
        let value = connection
            .query_row(query, params, |row| row.get::<_, String>(0))
            .optional()?;
        value
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(AppError::from)
    }

    pub fn enrich_device_history(
        &self,
        network_id: &str,
        devices: &mut [ObservedDevice],
    ) -> AppResult<()> {
        let connection = self.connection.lock();
        let mut seen_statement = connection.prepare(
            "SELECT first_seen FROM observed_devices
             WHERE network_id = ?1 AND identity_key = ?2",
        )?;
        let mut preference_statement = connection.prepare(
            "SELECT trust_state FROM device_preferences
             WHERE network_id = ?1 AND identity_key = ?2",
        )?;

        for device in devices {
            if let Some(first_seen) = seen_statement
                .query_row([network_id, &device.identity_key], |row| {
                    row.get::<_, String>(0)
                })
                .optional()?
            {
                if let Ok(parsed) = DateTime::parse_from_rfc3339(&first_seen) {
                    device.first_seen = parsed.with_timezone(&Utc);
                }
                device.is_new = false;
            }

            if let Some(value) = preference_statement
                .query_row([network_id, &device.identity_key], |row| {
                    row.get::<_, String>(0)
                })
                .optional()?
            {
                device.trust_state = parse_trust_state(&value);
            }
        }

        Ok(())
    }

    pub fn save_report(&self, report: &ScanReport) -> AppResult<()> {
        let payload = serde_json::to_string(report)?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;

        transaction.execute(
            "
            INSERT OR REPLACE INTO scans(id, completed_at, network_id, ssid, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ",
            params![
                report.id,
                report.completed_at.to_rfc3339(),
                report.network.network_id,
                report.network.ssid,
                payload
            ],
        )?;

        for device in &report.devices {
            transaction.execute(
                "
                INSERT INTO observed_devices(network_id, identity_key, first_seen, last_seen)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(network_id, identity_key) DO UPDATE SET
                    last_seen = excluded.last_seen
                ",
                params![
                    report.network.network_id,
                    device.identity_key,
                    device.first_seen.to_rfc3339(),
                    device.last_seen.to_rfc3339()
                ],
            )?;
        }

        transaction.execute(
            "
            DELETE FROM scans
            WHERE id NOT IN (
                SELECT id FROM scans ORDER BY completed_at DESC LIMIT 5000
            )
            ",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn history(&self, limit: usize) -> AppResult<Vec<HistoryEntry>> {
        let limit = i64::try_from(limit.min(200)).unwrap_or(200);
        let connection = self.connection.lock();
        let mut statement = connection.prepare(
            "
            SELECT payload_json
            FROM scans
            ORDER BY completed_at DESC
            LIMIT ?1
            ",
        )?;

        let rows = statement.query_map([limit], |row| row.get::<_, String>(0))?;
        let mut result = Vec::new();
        for row in rows {
            let report: ScanReport = serde_json::from_str(&row?)?;
            result.push(HistoryEntry {
                id: report.id,
                completed_at: report.completed_at,
                ssid: report.network.ssid,
                security: report.network.security,
                risk: report.assessment.risk,
                visibility: report.assessment.visibility,
                device_count: report.devices.len(),
                new_device_count: report.devices.iter().filter(|item| item.is_new).count(),
                mode: report.mode,
            });
        }
        Ok(result)
    }

    pub fn report(&self, id: &str) -> AppResult<Option<ScanReport>> {
        self.load_optional_report("SELECT payload_json FROM scans WHERE id = ?1", [id])
    }

    pub fn set_device_trust(
        &self,
        network_id: &str,
        identity_key: &str,
        trust_state: TrustState,
    ) -> AppResult<()> {
        self.connection.lock().execute(
            "
            INSERT INTO device_preferences(network_id, identity_key, trust_state, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(network_id, identity_key) DO UPDATE SET
                trust_state = excluded.trust_state,
                updated_at = excluded.updated_at
            ",
            params![
                network_id,
                identity_key,
                trust_state_name(trust_state),
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }
}

fn migrate_network_ids(connection: &mut Connection) -> AppResult<()> {
    let reports = {
        let mut statement = connection.prepare("SELECT id, network_id, payload_json FROM scans")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    let mut migrations = Vec::new();
    for (id, old_network_id, payload) in reports {
        let mut report: ScanReport = serde_json::from_str(&payload)?;
        let canonical_network_id = stable_network_id(
            report.network.ssid.as_deref(),
            report.network.bssid.as_deref(),
            report.network.router.as_deref(),
            report.network.subnet.as_deref(),
            report.network.interface_name.as_deref(),
        );
        if canonical_network_id == old_network_id {
            continue;
        }
        report.network.network_id.clone_from(&canonical_network_id);
        migrations.push((
            id,
            old_network_id,
            canonical_network_id,
            serde_json::to_string(&report)?,
        ));
    }

    if migrations.is_empty() {
        return Ok(());
    }

    let transaction = connection.transaction()?;
    for (scan_id, old_network_id, canonical_network_id, payload) in migrations {
        transaction.execute(
            "
            INSERT INTO observed_devices(network_id, identity_key, first_seen, last_seen)
            SELECT ?1, identity_key, first_seen, last_seen
            FROM observed_devices
            WHERE network_id = ?2
            ON CONFLICT(network_id, identity_key) DO UPDATE SET
                first_seen = MIN(first_seen, excluded.first_seen),
                last_seen = MAX(last_seen, excluded.last_seen)
            ",
            params![canonical_network_id, old_network_id],
        )?;
        transaction.execute(
            "
            INSERT INTO device_preferences(network_id, identity_key, trust_state, updated_at)
            SELECT ?1, identity_key, trust_state, updated_at
            FROM device_preferences
            WHERE network_id = ?2
            ON CONFLICT(network_id, identity_key) DO UPDATE SET
                trust_state = excluded.trust_state,
                updated_at = excluded.updated_at
            WHERE excluded.updated_at > device_preferences.updated_at
            ",
            params![canonical_network_id, old_network_id],
        )?;
        transaction.execute(
            "
            UPDATE scans
            SET network_id = ?1, payload_json = ?2
            WHERE id = ?3
            ",
            params![canonical_network_id, payload, scan_id],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn trust_state_name(value: TrustState) -> &'static str {
    match value {
        TrustState::Unknown => "unknown",
        TrustState::Mine => "mine",
        TrustState::Known => "known",
        TrustState::Ignored => "ignored",
    }
}

fn parse_trust_state(value: &str) -> TrustState {
    match value {
        "mine" => TrustState::Mine,
        "known" => TrustState::Known,
        "ignored" => TrustState::Ignored,
        _ => TrustState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::Utc;
    use rusqlite::params;

    use super::{Storage, migrate_network_ids};
    use crate::domain::{
        AppSettings, Assessment, Confidence, NetworkContext, ScanCoverage, ScanMode, ScanReport,
        Severity, TrustState, VisibilityLevel,
    };
    use crate::fingerprint::{RawDevice, finalize_device};
    use crate::network::stable_network_id;

    fn report_with_network_id(network_id: &str) -> ScanReport {
        let now = Utc::now();
        ScanReport {
            id: "legacy-scan".to_owned(),
            started_at: now,
            completed_at: now,
            duration_ms: 1,
            mode: ScanMode::Safe,
            network: NetworkContext {
                connected: true,
                wifi_available: true,
                interface_name: Some("en0".to_owned()),
                ssid: Some("Home".to_owned()),
                bssid: Some("00:11:22:33:44:55".to_owned()),
                security: "wpa3-personal".to_owned(),
                phy_mode: None,
                channel: None,
                rssi: None,
                noise: None,
                signal_quality: None,
                transmit_rate_mbps: None,
                country_code: None,
                local_mac_address: None,
                ipv4: Some("192.168.1.20".to_owned()),
                ipv6: Vec::new(),
                subnet: Some("192.168.1.0/24".to_owned()),
                router: Some("192.168.1.1".to_owned()),
                dns_servers: Vec::new(),
                proxy_enabled: false,
                vpn_active: false,
                network_id: network_id.to_owned(),
            },
            devices: vec![finalize_device(
                RawDevice::new(Ipv4Addr::new(192, 168, 1, 42)),
                now,
            )],
            assessment: Assessment {
                risk: Severity::Info,
                visibility: VisibilityLevel::Partial,
                confidence: Confidence::Medium,
                summary: "test".to_owned(),
                findings: Vec::new(),
            },
            coverage: ScanCoverage {
                target_count: 1,
                responsive_count: 1,
                arp_count: 1,
                mdns_count: 0,
                ssdp_count: 0,
                onvif_count: 0,
                methods: Vec::new(),
                limited_by_subnet_size: false,
                notes: Vec::new(),
            },
        }
    }

    #[test]
    fn stores_and_loads_settings() {
        let storage = Storage::in_memory().expect("in-memory database");
        let settings = AppSettings {
            background_monitoring: false,
            monitoring_interval_seconds: 90,
            default_scan_mode: ScanMode::Deep,
            notify_new_devices: false,
            notify_network_changes: true,
        };

        storage.save_settings(&settings).expect("save settings");
        assert_eq!(storage.settings().expect("load settings"), settings);
    }

    #[test]
    fn device_first_seen_is_scoped_to_the_wifi_network() {
        let storage = Storage::in_memory().expect("in-memory database");
        let mut device =
            finalize_device(RawDevice::new(Ipv4Addr::new(192, 168, 1, 42)), Utc::now());
        storage
            .connection
            .lock()
            .execute(
                "INSERT INTO observed_devices(network_id, identity_key, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    "home-network",
                    device.identity_key,
                    device.first_seen.to_rfc3339(),
                    device.last_seen.to_rfc3339()
                ],
            )
            .expect("insert observation");

        storage
            .enrich_device_history("hotel-network", std::slice::from_mut(&mut device))
            .expect("enrich other network");
        assert!(device.is_new);

        storage
            .enrich_device_history("home-network", std::slice::from_mut(&mut device))
            .expect("enrich same network");
        assert!(!device.is_new);
    }

    #[test]
    fn device_trust_is_scoped_to_the_wifi_network() {
        let storage = Storage::in_memory().expect("in-memory database");
        let mut home_device =
            finalize_device(RawDevice::new(Ipv4Addr::new(192, 168, 1, 42)), Utc::now());
        let mut hotel_device = home_device.clone();

        storage
            .set_device_trust("home-network", &home_device.identity_key, TrustState::Mine)
            .expect("save trust");
        storage
            .enrich_device_history("home-network", std::slice::from_mut(&mut home_device))
            .expect("enrich home device");
        storage
            .enrich_device_history("hotel-network", std::slice::from_mut(&mut hotel_device))
            .expect("enrich hotel device");

        assert_eq!(home_device.trust_state, TrustState::Mine);
        assert_eq!(hotel_device.trust_state, TrustState::Unknown);
    }

    #[test]
    fn migrates_trust_when_wifi_metadata_visibility_changes() {
        let storage = Storage::in_memory().expect("in-memory database");
        let legacy_network_id = "legacy-visible-network";
        let report = report_with_network_id(legacy_network_id);
        let identity_key = report.devices[0].identity_key.clone();
        storage.save_report(&report).expect("save legacy report");
        storage
            .set_device_trust(legacy_network_id, &identity_key, TrustState::Known)
            .expect("save legacy trust");

        {
            let mut connection = storage.connection.lock();
            migrate_network_ids(&mut connection).expect("migrate network identifiers");
        }

        let canonical_network_id = stable_network_id(
            None,
            None,
            Some("192.168.1.1"),
            Some("192.168.1.0/24"),
            Some("en0"),
        );
        let latest = storage
            .latest_report()
            .expect("load latest report")
            .expect("report exists");

        assert_eq!(latest.network.network_id, canonical_network_id);
        assert_eq!(latest.devices[0].trust_state, TrustState::Known);
    }
}
