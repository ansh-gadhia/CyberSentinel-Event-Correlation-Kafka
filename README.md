# Event Correlation Workflow with Kafka

A pipeline for ingesting, processing, and correlating security events from Wazuh alerts using Apache Kafka.

---

## Prerequisites

- Linux-based OS (Ubuntu/Debian recommended)
- Python 3.x
- Docker & Docker Compose
- SSH access to the SOC agent at `192.168.1.222`
- `sshfs` installed on the host machine

---

## Setup & Deployment

### 1. Copy Required Files from the Repository

Clone or copy the necessary project files to your working directory:

```bash
git clone https://github.com/ansh-gadhia/CyberSentinel-Event-Correlation-Kafka.git
cd CyberSentinel-Event-Correlation-Kafka
```

Or manually copy the required files:

```bash
cp -r /path/to/repo/files /your/working/directory
```

---

### 2. Install Docker & Docker Compose

```bash
# Install Docker
sudo apt update
sudo apt install -y docker.io

# Install Docker Compose
sudo apt install -y docker-compose

# (Optional) Allow running Docker without sudo
sudo usermod -aG docker $USER
newgrp docker
```

Verify installation:

```bash
docker --version
docker-compose --version
```

---

### 3. Install Python Dependencies

Install the required Python packages. Choose either option:

**Option A — System-wide install:**
```bash
pip install confluent-kafka --break-system-packages
pip install geoip2 --break-system-packages
```

**Option B — Virtual environment (recommended):**
```bash
python3 -m venv venv
source venv/bin/activate
pip install confluent-kafka geoip2
```

---

### 4. Start Kafka Services with Docker Compose

Bring up Kafka and any dependent services in detached mode:

```bash
sudo docker-compose up -d
```

Verify containers are running:

```bash
sudo docker-compose ps
```

---

### 5. Create the Alerts Mount Directory

Create the local directory that will serve as the mount point for remote Wazuh alerts:

```bash
mkdir /mnt/alerts
```

---

### 6. Mount the Remote Alerts Directory via SSHFS

Mount the Wazuh alerts directory from the remote SOC agent:

```bash
sudo sshfs -o allow_other,reconnect,ServerAliveInterval=15,cache=no,dir_cache=no \
    soc@192.168.1.222:/var/ossec/logs/alerts /mnt/alerts
```

> **Note:** Ensure `user_allow_other` is enabled in `/etc/fuse.conf` for the `allow_other` option to work.

Verify the mount:

```bash
ls /mnt/alerts
```

---

### 7. Run the Pipeline

Start the event correlation pipeline, pointing it at the mounted alerts file and your Kafka broker:

```bash
sudo python3 pipeline.py \
    --input /mnt/alerts/alerts.json \
    --kafka-brokers localhost:9092 \
    --all \
    --skip-existing
```

**Flag Reference:**

| Flag | Description |
|---|---|
| `--input` | Path to the Wazuh alerts JSON file |
| `--kafka-brokers` | Kafka broker address (host:port) |
| `--all` | Process all event types |
| `--skip-existing` | Skip events that have already been ingested |

---

## Quick Reference — Full Setup Sequence

```bash
# 1. Copy files
git clone <your-repository-url> && cd <project-directory>

# 2. Install Docker
sudo apt update && sudo apt install -y docker.io docker-compose

# 3. Install Python dependencies
pip install confluent-kafka geoip2 --break-system-packages

# 4. Start services
sudo docker-compose up -d

# 5. Create mount point
mkdir /mnt/alerts

# 6. Mount remote alerts
sudo sshfs -o allow_other,reconnect,ServerAliveInterval=15,cache=no,dir_cache=no \
    soc@192.168.1.222:/var/ossec/logs/alerts /mnt/alerts

# 7. Run pipeline
sudo python3 pipeline.py \
    --input /mnt/alerts/alerts.json \
    --kafka-brokers localhost:9092 \
    --all \
    --skip-existing
```

---

## Troubleshooting

- **SSHFS mount fails** — Ensure `sshfs` is installed (`sudo apt install sshfs`) and that SSH key-based auth is configured for `soc@192.168.1.222`.
- **Kafka connection refused** — Confirm Docker containers are running with `sudo docker-compose ps` and that port `9092` is not blocked by a firewall.
- **Permission denied on `/mnt/alerts`** — Run `sudo chmod 755 /mnt/alerts` and verify `user_allow_other` is uncommented in `/etc/fuse.conf`.
- **`confluent-kafka` install fails** — Try installing system dependencies first: `sudo apt install -y librdkafka-dev`.

---

## License

This project is intended for internal SOC use. Refer to your organization's policy for distribution and usage guidelines.