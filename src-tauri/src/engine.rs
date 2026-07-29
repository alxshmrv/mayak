use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

use crate::discovery::discover;
use crate::domain::{ScanMode, ScanProgress, ScanReport};
use crate::error::{AppError, AppResult};
use crate::network::collect_network_context;
use crate::risk::assess;
use crate::storage::Storage;

pub struct ScanEngine {
    storage: Arc<Storage>,
    scan_lock: Mutex<()>,
}

impl ScanEngine {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self {
            storage,
            scan_lock: Mutex::new(()),
        }
    }

    pub async fn scan(
        &self,
        mode: ScanMode,
        progress: Option<UnboundedSender<ScanProgress>>,
    ) -> AppResult<ScanReport> {
        let Ok(_guard) = self.scan_lock.try_lock() else {
            return Err(AppError::ScanInProgress);
        };
        let started_at = Utc::now();
        let timer = Instant::now();

        if let Some(sender) = progress.as_ref() {
            let _ = sender.send(ScanProgress {
                phase: "network".to_owned(),
                title: "Читаем параметры Wi‑Fi".to_owned(),
                detail: "CoreWLAN, маршруты, DNS и сетевые интерфейсы".to_owned(),
                completed: 0,
                total: 1,
            });
        }

        let network = tokio::task::spawn_blocking(collect_network_context)
            .await
            .map_err(|error| AppError::Platform(error.to_string()))??;
        let previous = self
            .storage
            .latest_report_for_ssid(network.ssid.as_deref())?;
        let output = Box::pin(discover(&network, mode, progress.as_ref())).await?;
        let mut devices = output.devices;
        self.storage
            .enrich_device_history(&network.network_id, &mut devices)?;
        let assessment = assess(&network, &devices, &output.coverage, previous.as_ref());
        let completed_at = Utc::now();
        let report = ScanReport {
            id: Uuid::new_v4().to_string(),
            started_at,
            completed_at,
            duration_ms: u64::try_from(timer.elapsed().as_millis()).unwrap_or(u64::MAX),
            mode,
            network,
            devices,
            assessment,
            coverage: output.coverage,
        };
        self.storage.save_report(&report)?;

        if let Some(sender) = progress {
            let _ = sender.send(ScanProgress {
                phase: "complete".to_owned(),
                title: "Проверка завершена".to_owned(),
                detail: format!(
                    "Наблюдается {} устройств за {:.1} с",
                    report.devices.len(),
                    Duration::from_millis(report.duration_ms).as_secs_f64()
                ),
                completed: 1,
                total: 1,
            });
        }

        Ok(report)
    }
}
