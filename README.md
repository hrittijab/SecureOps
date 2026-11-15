
# SecureOps

### Event-Driven Application Security & Threat Detection Platform

SecureOps is a security engineering platform designed to collect authentication telemetry, detect suspicious activity, correlate security alerts, and persist incidents for investigation.

The project combines a Java/Spring Boot authentication service, Apache Kafka event streaming, PostgreSQL persistence, Python-based detection engines, and experimental machine-learning anomaly detection.

SecureOps explores how backend systems can incorporate security monitoring, reliable event delivery, automated threat detection, and incident response workflows.

## Technology Stack

| Area | Technologies |
|---|---|
| Backend | Java 21, Spring Boot, REST APIs |
| Event Streaming | Apache Kafka 3.9.1 |
| Database | PostgreSQL 17 |
| Threat Detection | Python, rule-based detection |
| Machine Learning | scikit-learn, Isolation Forest |
| Infrastructure | Docker, Docker Compose |
| Testing | pytest, JUnit, Maven |
| Database Migrations | Flyway, SQL |

## System Architecture

```text
                  +------------------------+
                  |   Client / API Calls   |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  |   Spring Boot Auth API |
                  |   Authentication       |
                  |   Security Telemetry   |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | PostgreSQL Outbox      |
                  | Transactional Events   |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | Outbox Publisher       |
                  | Retry / Backoff        |
                  | Claim Leasing          |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | Apache Kafka           |
                  | security-events.v1     |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | Python Kafka Consumer  |
                  | Event Validation       |
                  | Deduplication          |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | PostgreSQL Event Store |
                  | kafka_ingested_events  |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | Incremental Detection  |
                  | Checkpoint Processing  |
                  | Event-Time Lookback    |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | Threat Detection Rules |
                  | Brute Force / Spraying |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | Incident Correlation   |
                  | Evidence Association   |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | PostgreSQL Incidents   |
                  | Persistent Evidence    |
                  +------------------------+
```

## Core Features

### 1. Authentication and Security Telemetry

The authentication service is implemented using Java 21 and Spring Boot.

It provides authentication-related functionality and generates security telemetry associated with authentication activity.

Security events are persisted through a transactional outbox rather than relying exclusively on direct synchronous message publication.

This architecture helps separate authentication processing from asynchronous event delivery.

### 2. Reliable Event Streaming with Apache Kafka

SecureOps integrates Apache Kafka to transport authentication security events between the backend service and the Python detection pipeline.

**Kafka topic:** `secureops.security-events.v1`

The event-streaming implementation includes:

- PostgreSQL-backed transactional outbox
- Asynchronous outbox publisher
- Retry and backoff handling
- Claim leasing for outbox records
- Kafka event consumption
- JSON event validation
- Database-backed event deduplication
- Kafka offset commits after successful database persistence

Broker outage and recovery scenarios were tested to evaluate event delivery behavior.

The architecture is designed around at-least-once delivery with idempotent database ingestion rather than assuming exactly-once end-to-end processing.

### 3. Authentication Threat Detection

SecureOps implements deterministic rules for five authentication attack patterns:

| Threat | Detection Objective |
|---|---|
| Brute Force | Identify concentrated repeated authentication failures |
| Slow Brute Force | Identify repeated failures distributed over longer periods |
| Password Spraying | Identify attempts against multiple accounts |
| Slow Password Spraying | Identify low-frequency spraying behavior |
| Distributed Password Spraying | Identify suspicious activity distributed across source IPs |

Distributed password spraying is treated as a review-oriented detection category.

The rule-based engine is the primary detection mechanism.

### 4. Incremental Detection Pipeline

The detection pipeline supports checkpoint-based processing of newly ingested security events.

Instead of repeatedly scanning the complete event history, the incremental worker:

1. Reads newly ingested events after the saved checkpoint.
2. Loads a bounded event-time lookback window.
3. Runs the threat detection engine.
4. Correlates detected alerts with security incidents.
5. Persists incidents and associated evidence.
6. Advances the checkpoint within the database transaction.

This approach reduces unnecessary historical rescanning while maintaining context for recent authentication activity.

**Current limitations:** The implementation assumes a single detection worker and uses a bounded lookback. Late-arriving events outside the lookback may not be detected.

### 5. Incident Correlation and Persistence

SecureOps groups related security alerts into persistent incidents.

Incident records are stored in PostgreSQL alongside supporting evidence.

The persistence layer supports:

- Incident creation and updates
- Evidence association
- Correlation using overlapping evidence
- Idempotency in tested processing scenarios
- Transactional checkpoint updates
- Rollback when detection processing fails

Relevant database tables include:

```text
security_incidents
security_incident_evidence
detection_checkpoints
kafka_ingested_events
```

### 6. Experimental Machine-Learning Detection

SecureOps also includes an experimental anomaly detection pipeline based on Isolation Forest.

The ML detector analyzes authentication traffic features such as:

- Request volume
- Authentication failure rates
- Distinct account counts
- Source IP diversity
- Failure concentration

The ML implementation is evaluated alongside the deterministic rule-based engine to study detection coverage and false-positive trade-offs.

Machine learning is not used for automatic blocking.

---

## Security Evaluation

### Evaluation Methodology

The benchmark uses reproducible synthetic authentication traffic with separate training, validation, and final-test periods.

**Configuration:**

| Parameter | Value |
|---|---|
| ML algorithm | Isolation Forest |
| Candidate windows | 60, 300, 900 seconds |
| Selected window | 300 seconds |
| Selected anomaly threshold | 0.03363737880038309 |
| Final evaluation duration | 14 days |
| Attack scenarios | 4 |

The evaluated attack scenarios were:

1. Brute force
2. Password spraying
3. Distributed password spraying
4. Slow brute force

Model selection was performed using validation data before final evaluation.

### Final Benchmark Results

| Metric | Rule-Based Detector | ML Detector |
|---|---|---|
| Attack scenarios detected | 4/4 | 4/4 |
| Alerts / flagged windows | 5 alerts | 110 windows |
| Benign-only alerts / false-positive windows | 0 alerts | 102 windows |
| Attack-window recall | Not measured | 80% |
| Precision | Not directly comparable | 7.27% |
| False-positive rate | Not directly comparable | 3.62% |

The ML detector correctly flagged 8 of 10 attack-containing windows, including 5 of 7 windows associated with slow brute-force activity.

The rule-based detector generated five attack-related alerts without benign-only alerts in this benchmark.

One password-spray scenario triggered two different rules.

**Important:** Rule-generated alerts and ML window classifications are different evaluation units. Their false-positive counts should not be interpreted as directly comparable.

### Engineering Conclusions

The rule-based detector remains the primary mechanism for authentication threat detection.

The ML pipeline provides an experimental approach to analyzing behavioral anomalies and investigating potential detection gaps.

The benchmark illustrates a trade-off between anomaly sensitivity and false-positive volume.

These results do not establish production performance because the evaluation uses synthetic traffic, a limited attack set, and related traffic generators across datasets.

---

## End-to-End Verification

The Kafka-backed detection pipeline was tested using simulated authentication failures.

One end-to-end test produced:

| Metric | Result |
|---|---|
| Failed authentication attempts | 6 |
| Kafka security events | 6 |
| Brute-force alerts | 1 |
| Correlated incidents | 1 |
| Incident severity | MEDIUM |
| Incident risk score | 45 |
| Supporting evidence records | 6 |

The detection engine identified a HIGH-severity brute-force alert, which was correlated into a MEDIUM-severity incident based on the incident scoring logic.

The incident and supporting evidence were successfully persisted to PostgreSQL.

## Testing and Validation

SecureOps has undergone automated testing and targeted integration verification.

### Python Tests

**225 Python tests passed.**

The test suite covers functionality across the security detection and incident-processing components, including Kafka ingestion, offset safety, incident persistence, and detection workflows.

Run the Python tests from the repository root:

```powershell
python -m pytest -q
```

### Java Tests

The Spring Boot authentication service successfully passed Maven verification with its required database and JWT configuration available.

Run from the authentication service directory:

```powershell
cd services/auth-service
mvn verify
```

The application requires a running PostgreSQL database and configured environment variables, including:

```text
DB_PASSWORD
JWT_PRIVATE_KEY
JWT_PUBLIC_KEY
```

The JWT configuration expects filesystem paths to the PEM key files.

**Never commit private keys, database passwords, or other secrets to the repository.**

### Additional Verification

The following scenarios were tested:

- Kafka broker outage and recovery
- Event publishing through the transactional outbox
- Kafka consumer ingestion
- Duplicate-event handling
- Offset safety following database persistence
- Incremental detection processing
- Detection checkpoint persistence
- Transaction rollback on processing failure
- Incident and evidence persistence
- Database schema restoration into an isolated test database

---

## Project Structure

```text
SecureOps/
|
|-- services/
|   |-- auth-service/
|       |-- src/
|       |-- pom.xml
|
|-- streaming/
|   |-- kafka_consumer.py
|   |-- event_adapter.py
|   |-- event_loader.py
|   |-- incremental_loader.py
|   |-- incremental_worker.py
|   |-- windowed_detection.py
|   |-- detection_runner.py
|   |-- checkpoint.py
|
|-- incidents/
|   |-- persistence.py
|
|-- dashboard_api/
|   |-- main.py
|
|-- db/
|   |-- migrations/
|       |-- secureops_schema.sql
|
|-- ml/
|
|-- tests/
|
|-- docker-compose.yml
|
|-- README.md
```

This structure highlights the main event-streaming and detection components. The repository also contains supporting modules, evaluation scripts, and additional security functionality.

---

## Local Development

### Prerequisites

- Java 21
- Maven
- Python and project dependencies
- Docker and Docker Compose
- PostgreSQL 17
- Apache Kafka

### 1. Clone the Repository

```powershell
git clone https://github.com/hrittijab/SecureOps.git
cd SecureOps
```

### 2. Start the Infrastructure

Use the project's Docker Compose configuration to start the required local infrastructure.

```powershell
docker compose up -d
```

Ensure that the PostgreSQL and Kafka containers are running before starting the dependent services.

### 3. Configure Environment Variables

The Spring Boot authentication service uses environment variables for database connectivity and JWT signing keys.

Example PowerShell configuration:

```powershell
$env:DB_URL = "jdbc:postgresql://localhost:5433/secureops_auth"
$env:DB_USERNAME = "secureops"

$env:DB_PASSWORD = Read-Host "Database password"

$env:JWT_PRIVATE_KEY = (Resolve-Path "secrets/jwt-private.pem").Path
$env:JWT_PUBLIC_KEY = (Resolve-Path "secrets/jwt-public.pem").Path
```

Create a local RSA key pair if one is not already available. Store private keys outside version control.

The example assumes that the database has been initialized and that the JWT key files exist.

### 4. Run the Authentication Service

```powershell
cd services/auth-service
mvn spring-boot:run
```

The local authentication service is configured to use port `8081`.

### 5. Run Automated Tests

From the repository root:

```powershell
python -m pytest -q
```

For the authentication service:

```powershell
cd services/auth-service
mvn verify
```

### 6. Reproduce the ML Evaluation

From the repository root:

```powershell
python -m ml.window_selection
python -m ml.final_evaluate
python -m ml.final_compare
```

### Database Schema

The repository includes:

```text
db/migrations/secureops_schema.sql
```

This SQL file contains the exported schema for the event-ingestion, incident-persistence, and detection-checkpoint tables.

It was verified through restoration into a separate test database.

It is a schema snapshot and should not be confused with an automatically applied Flyway migration.

---

## Engineering Design Decisions

### Transactional Outbox

The authentication service persists events before asynchronous Kafka publication, reducing the risk of losing security telemetry when the broker is temporarily unavailable.

### Idempotent Event Processing

Kafka consumers may receive duplicate messages during retries or recovery. Database uniqueness constraints help prevent duplicate event ingestion.

### Database-First Offset Safety

Kafka offsets are committed only after successful database persistence, allowing messages to be retried when persistence fails.

### Incremental Processing

Checkpoint-based detection avoids repeatedly processing the entire historical event dataset.

### Rule-Based and ML Detection

Deterministic rules provide explainable authentication detections. The experimental ML component allows comparison against anomaly-based methods.

---

## Current Limitations and Future Work

SecureOps is a security engineering portfolio project and experimental platform, not a production-managed SIEM.

Current limitations include:

- Evaluation based primarily on synthetic authentication traffic
- Limited attack-scenario coverage
- Single-worker incremental detection assumptions
- Bounded handling of late-arriving events
- Experimental ML detection with substantial false-positive trade-offs
- No automatic blocking based on ML classifications
- Additional deployment hardening and operational monitoring required

Potential future improvements include:

- Continuous worker orchestration
- More robust late-event handling
- Expanded real-world traffic evaluation
- Additional detection rules
- Incident investigation dashboard enhancements
- Deployment automation and observability improvements

## Author

**Hrittija Bhattacharjee**

- GitHub: https://github.com/hrittijab
- LinkedIn: https://www.linkedin.com/in/hrittija/
