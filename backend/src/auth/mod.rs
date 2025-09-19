pub mod paseto;
pub mod pw;
pub mod ses;
pub mod behavioral;
pub mod audit;
pub mod threat;
pub mod binding;
pub mod utils;

pub use paseto::{Claims, PasetoManager};
pub use pw::{hash_password, verify_password};
pub use ses::{SessionManager, SecurityManager, SessionAnalytics};
pub use behavioral::{BehaviorAnalytics, GeoLocation};
pub use audit::{AuditEvent, AuditEventType, EventOutcome, EventSeverity, AuditManager};
pub use threat::{ThreatDetectionEngine, ActiveThreat, ThreatType, ThreatEvaluationResult};
pub use binding::{SessionBindingManager, CryptographicSessionBinding, DeviceFingerprint, TlsFingerprint};
