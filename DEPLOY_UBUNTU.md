# Deploying ARMSS Gateway Backend on Ubuntu with Docker

This guide explains how to build and run the **ARMSS Gateway Backend** on an Ubuntu machine using Docker and Docker Compose.

---

## 1. Prerequisites (Install Docker on Ubuntu)

If Docker is not already installed on your Ubuntu machine, run:

```bash
# Update package lists
sudo apt update

# Install Docker and Docker Compose plugin
sudo apt install -y docker.io docker-compose-v2

# Start and enable Docker service
sudo systemctl enable --now docker

# Optional: Allow running docker without sudo
sudo usermod -aG docker $USER
newgrp docker
```

---

## 2. Transfer / Place Project Files

Navigate to your project directory on Ubuntu:

```bash
cd /path/to/armss_gateway_backend
```

Ensure the following files are present:
- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- `migrations/`
- `cmd/`
- `internal/`
- `go.mod` & `go.sum`
- `.env`

---

## 3. Configure the `.env` File

Create or edit your `.env` file:

```bash
cp .env.example .env
nano .env
```

### Important Database Configuration (`DB_HOST`):
- **If MySQL is running directly on the Ubuntu host (e.g. system `mysql-server`)**:
  Set:
  ```env
  DB_HOST=host.docker.internal
  DB_PORT=3306
  DB_USER=root
  DB_PASSWORD=your_mysql_password
  DB_NAME=armss_gateway_db
  ```
  *(Note: In Ubuntu `/etc/mysql/mysql.conf.d/mysqld.cnf`, ensure `bind-address = 0.0.0.0` or `127.0.0.1,172.17.0.1` so Docker containers can connect).*

- **If MySQL is on a separate remote database server**:
  ```env
  DB_HOST=192.168.1.100  # or your database server IP
  ```

---

## 4. Build and Run the Container

Run the following command to build the Docker image and start the container in the background:

```bash
docker compose up -d --build
```

---

## 5. Verify the Server is Running

### Check container status:
```bash
docker compose ps
```

### View real-time logs:
```bash
docker compose logs -f gateway-backend
```

### Test API connectivity:
```bash
curl http://localhost:2092/api/v1/health
```

---

## 6. Common Maintenance Commands

- **Stop the server:**
  ```bash
  docker compose down
  ```

- **Restart the server:**
  ```bash
  docker compose restart
  ```

- **Rebuild after making code changes:**
  ```bash
  docker compose up -d --build
  ```
