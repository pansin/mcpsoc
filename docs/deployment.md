# MCPSoc 部署指南

## 部署模式选择

MCPSoc 支持多种部署模式，适用于不同规模和需求的环境。

### 部署模式对比

| 部署模式 | 适用场景 | 复杂度 | 可扩展性 | 维护成本 |
|------------|----------|-------|----------|----------|
| Docker Compose | 开发测试、小规模部署 | 低 | 低 | 低 |
| Kubernetes | 生产环境、中大规模 | 中 | 高 | 中 |
| 云原生 | 企业级部署 | 高 | 高 | 高 |
| 单机部署 | 测试环境、学习 | 低 | 低 | 低 |

## 系统要求

### 硬件要求

**最小配置** (开发/测试环境):
- CPU: 2 核
- 内存: 4GB
- 存储: 20GB SSD
- 网络: 100Mbps

**推荐配置** (生产环境):
- CPU: 8 核
- 内存: 16GB
- 存储: 100GB SSD
- 网络: 1Gbps

**高可用配置** (企业环境):
- CPU: 16+ 核
- 内存: 32GB+
- 存储: 500GB+ NVMe SSD
- 网络: 10Gbps

### 软件依赖

- **操作系统**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Docker**: >= 20.10
- **Docker Compose**: >= 2.0 (可选)
- **Kubernetes**: >= 1.24 (可选)
- **PostgreSQL**: >= 14 (TimescaleDB 推荐)
- **Redis**: >= 6.0
- **ArangoDB**: >= 3.10 (可选)

## Docker Compose 部署

### 快速开始

1. **克隆项目**
```bash
git clone https://github.com/mcpsoc/mcpsoc.git
cd mcpsoc
```

2. **编辑配置文件**
```bash
cp .env.example .env
vim .env
```

```bash
# .env 文件配置
MCPSOC_VERSION=latest
DATABASE_PASSWORD=your_secure_password
REDIS_PASSWORD=your_redis_password
JWT_SECRET=your_jwt_secret
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
```

3. **启动服务**
```bash
docker-compose up -d
```

4. **初始化数据库**
```bash
docker-compose exec mcpsoc-host mcpsoc db migrate
docker-compose exec mcpsoc-host mcpsoc db seed
```

5. **验证部署**
```bash
curl http://localhost:8080/health
```

### 完整配置文件

```yaml
# docker-compose.yml
version: '3.8'

services:
  mcpsoc-host:
    image: mcpsoc/host:${MCPSOC_VERSION:-latest}
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://mcpsoc:${DATABASE_PASSWORD}@postgres:5432/mcpsoc
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
      - ARANGODB_URL=http://arangodb:8529
      - JWT_SECRET=${JWT_SECRET}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - LOG_LEVEL=info
    depends_on:
      - postgres
      - redis
      - arangodb
    restart: unless-stopped
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
    networks:
      - mcpsoc-network

  mcpsoc-agent:
    image: mcpsoc/agent:${MCPSOC_VERSION:-latest}
    environment:
      - MCPSOC_HOST_URL=http://mcpsoc-host:8080
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    depends_on:
      - mcpsoc-host
      - redis
    restart: unless-stopped
    volumes:
      - ./models:/app/models
    networks:
      - mcpsoc-network

  postgres:
    image: timescale/timescaledb:latest-pg14
    environment:
      - POSTGRES_DB=mcpsoc
      - POSTGRES_USER=mcpsoc
      - POSTGRES_PASSWORD=${DATABASE_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init-db.sql
    ports:
      - "5432:5432"
    restart: unless-stopped
    networks:
      - mcpsoc-network

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped
    networks:
      - mcpsoc-network

  arangodb:
    image: arangodb:3.10
    environment:
      - ARANGO_ROOT_PASSWORD=${DATABASE_PASSWORD}
    volumes:
      - arangodb_data:/var/lib/arangodb3
    ports:
      - "8529:8529"
    restart: unless-stopped
    networks:
      - mcpsoc-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - ./web/dist:/usr/share/nginx/html
    depends_on:
      - mcpsoc-host
    restart: unless-stopped
    networks:
      - mcpsoc-network

  # MCP Servers
  firewall-server:
    image: mcpsoc/firewall-server:${MCPSOC_VERSION:-latest}
    environment:
      - PFSENSE_HOST=${PFSENSE_HOST}
      - PFSENSE_USER=${PFSENSE_USER}
      - PFSENSE_PASSWORD=${PFSENSE_PASSWORD}
    restart: unless-stopped
    networks:
      - mcpsoc-network

  waf-server:
    image: mcpsoc/waf-server:${MCPSOC_VERSION:-latest}
    environment:
      - MODSECURITY_LOG_PATH=/var/log/modsecurity
    volumes:
      - /var/log/modsecurity:/var/log/modsecurity:ro
    restart: unless-stopped
    networks:
      - mcpsoc-network

volumes:
  postgres_data:
  redis_data:
  arangodb_data:

networks:
  mcpsoc-network:
    driver: bridge
```

### 生产环境优化

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  mcpsoc-host:
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 1G
          cpus: '0.5'
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  postgres:
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2.0'
    command: |
      postgres 
      -c shared_buffers=1GB
      -c effective_cache_size=3GB
      -c maintenance_work_mem=256MB
      -c checkpoint_completion_target=0.9
      -c wal_buffers=16MB
      -c default_statistics_target=100
      -c random_page_cost=1.1
      -c effective_io_concurrency=200
```

## Kubernetes 部署

### 系统架构

```
┌────────────────────────────────────────────────────┐
│                    Ingress Controller                    │
│              (NGINX / Traefik / Istio)                │
└────────────────────────────────────────────────────┘
                             │
┌────────────────────────────────────────────────────┐
│                  MCPSoc Application                   │
│  ┌─────────────┐ ┌──────────────────────────────┐  │
│  │ MCPSoc Host │ │      MCPSoc Agent        │  │
│  │  Service    │ │       Service           │  │
│  └─────────────┘ └──────────────────────────────┘  │
└────────────────────────────────────────────────────┘
                             │
┌────────────────────────────────────────────────────┐
│                   Data Layer                       │
│  ┌─────────────┐ ┌──────────┐ ┌────────────────┐  │
│  │PostgreSQL  │ │  Redis  │ │   ArangoDB    │  │
│  │(TimescaleDB)│ │        │ │    (可选)     │  │
│  └─────────────┘ └──────────┘ └────────────────┘  │
└────────────────────────────────────────────────────┘
```

### 部署步骤

1. **创建命名空间**
```bash
kubectl create namespace mcpsoc
```

2. **创建配置和密钥**
```bash
# 创建 ConfigMap
kubectl create configmap mcpsoc-config \
  --from-file=config/ \
  -n mcpsoc

# 创建 Secret
kubectl create secret generic mcpsoc-secrets \
  --from-literal=database-password=your_password \
  --from-literal=redis-password=your_redis_password \
  --from-literal=jwt-secret=your_jwt_secret \
  --from-literal=openai-api-key=your_openai_key \
  -n mcpsoc
```

3. **部署数据库**
```yaml
# postgresql.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgresql
  namespace: mcpsoc
spec:
  serviceName: postgresql
  replicas: 1
  selector:
    matchLabels:
      app: postgresql
  template:
    metadata:
      labels:
        app: postgresql
    spec:
      containers:
      - name: postgresql
        image: timescale/timescaledb:latest-pg14
        env:
        - name: POSTGRES_DB
          value: mcpsoc
        - name: POSTGRES_USER
          value: mcpsoc
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mcpsoc-secrets
              key: database-password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgresql-data
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "2Gi"
            cpu: "500m"
          limits:
            memory: "4Gi"
            cpu: "2"
  volumeClaimTemplates:
  - metadata:
      name: postgresql-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 50Gi
      storageClassName: ssd
---
apiVersion: v1
kind: Service
metadata:
  name: postgresql
  namespace: mcpsoc
spec:
  selector:
    app: postgresql
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
```

4. **部署 Redis**
```yaml
# redis.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: mcpsoc
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
        - redis-server
        - --requirepass
        - $(REDIS_PASSWORD)
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mcpsoc-secrets
              key: redis-password
        ports:
        - containerPort: 6379
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: mcpsoc
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
  type: ClusterIP
```

5. **部署 MCPSoc 应用**
```yaml
# mcpsoc-host.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcpsoc-host
  namespace: mcpsoc
spec:
  replicas: 2
  selector:
    matchLabels:
      app: mcpsoc-host
  template:
    metadata:
      labels:
        app: mcpsoc-host
    spec:
      containers:
      - name: mcpsoc-host
        image: mcpsoc/host:latest
        env:
        - name: DATABASE_URL
          value: postgresql://mcpsoc:$(DATABASE_PASSWORD)@postgresql:5432/mcpsoc
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mcpsoc-secrets
              key: database-password
        - name: REDIS_URL
          value: redis://:$(REDIS_PASSWORD)@redis:6379
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mcpsoc-secrets
              key: redis-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: mcpsoc-secrets
              key: jwt-secret
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: mcpsoc-secrets
              key: openai-api-key
        ports:
        - containerPort: 8080
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1"
        volumeMounts:
        - name: config
          mountPath: /app/config
      volumes:
      - name: config
        configMap:
          name: mcpsoc-config
---
apiVersion: v1
kind: Service
metadata:
  name: mcpsoc-host
  namespace: mcpsoc
spec:
  selector:
    app: mcpsoc-host
  ports:
  - port: 8080
    targetPort: 8080
  type: ClusterIP
```

6. **部署 Ingress**
```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mcpsoc-ingress
  namespace: mcpsoc
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - mcpsoc.example.com
    secretName: mcpsoc-tls
  rules:
  - host: mcpsoc.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: mcpsoc-host
            port:
              number: 8080
```

7. **执行部署**
```bash
kubectl apply -f postgresql.yaml
kubectl apply -f redis.yaml
kubectl apply -f mcpsoc-host.yaml
kubectl apply -f ingress.yaml

# 等待部署完成
kubectl get pods -n mcpsoc -w
```

8. **初始化数据库**
```bash
kubectl exec -it deployment/mcpsoc-host -n mcpsoc -- mcpsoc db migrate
kubectl exec -it deployment/mcpsoc-host -n mcpsoc -- mcpsoc db seed
```

### Helm 部署

使用 Helm Chart 简化 Kubernetes 部署：

```bash
# 添加 Helm Repository
helm repo add mcpsoc https://charts.mcpsoc.org
helm repo update

# 安装 MCPSoc
helm install mcpsoc mcpsoc/mcpsoc \
  --namespace mcpsoc \
  --create-namespace \
  --set host.image.tag=latest \
  --set postgresql.auth.password=your_password \
  --set redis.auth.password=your_redis_password \
  --set secrets.jwtSecret=your_jwt_secret \
  --set secrets.openaiApiKey=your_openai_key

# 更新部署
helm upgrade mcpsoc mcpsoc/mcpsoc -n mcpsoc

# 卸载
helm uninstall mcpsoc -n mcpsoc
```

## 云原生部署

### AWS EKS 部署

1. **创建 EKS 集群**
```bash
# 使用 eksctl
eksctl create cluster \
  --name mcpsoc-cluster \
  --region us-west-2 \
  --nodegroup-name mcpsoc-nodes \
  --node-type m5.large \
  --nodes 3 \
  --nodes-min 1 \
  --nodes-max 5 \
  --managed
```

2. **配置 AWS Load Balancer Controller**
```bash
# 安装 AWS Load Balancer Controller
kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller//crds?ref=master"

helm repo add eks https://aws.github.io/eks-charts
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  --set clusterName=mcpsoc-cluster \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller \
  -n kube-system
```

3. **使用 RDS 和 ElastiCache**
```yaml
# 使用 AWS RDS PostgreSQL
DATABASE_URL: postgresql://mcpsoc:password@mcpsoc-db.cluster-xyz.us-west-2.rds.amazonaws.com:5432/mcpsoc

# 使用 AWS ElastiCache Redis
REDIS_URL: redis://mcpsoc-cache.abc123.cache.amazonaws.com:6379
```

### Azure AKS 部署

1. **创建 AKS 集群**
```bash
# 创建资源组
az group create --name mcpsoc-rg --location eastus

# 创建 AKS 集群
az aks create \
  --resource-group mcpsoc-rg \
  --name mcpsoc-cluster \
  --node-count 3 \
  --node-vm-size Standard_D2s_v3 \
  --enable-addons monitoring \
  --generate-ssh-keys

# 获取凭据
az aks get-credentials --resource-group mcpsoc-rg --name mcpsoc-cluster
```

2. **使用 Azure Database 和 Cache**
```bash
# 创建 Azure Database for PostgreSQL
az postgres server create \
  --resource-group mcpsoc-rg \
  --name mcpsoc-postgres \
  --admin-user mcpsoc \
  --admin-password your_password \
  --sku-name GP_Gen5_2

# 创建 Azure Cache for Redis
az redis create \
  --resource-group mcpsoc-rg \
  --name mcpsoc-redis \
  --location eastus \
  --sku Premium \
  --vm-size P1
```

### Google GKE 部署

1. **创建 GKE 集群**
```bash
# 创建 GKE 集群
gcloud container clusters create mcpsoc-cluster \
  --zone us-central1-a \
  --num-nodes 3 \
  --machine-type n1-standard-2 \
  --enable-autoscaling \
  --min-nodes 1 \
  --max-nodes 5

# 获取凭据
gcloud container clusters get-credentials mcpsoc-cluster --zone us-central1-a
```

2. **使用 Cloud SQL 和 Memorystore**
```bash
# 创建 Cloud SQL PostgreSQL
gcloud sql instances create mcpsoc-postgres \
  --database-version POSTGRES_14 \
  --tier db-n1-standard-2 \
  --region us-central1

# 创建 Memorystore Redis
gcloud redis instances create mcpsoc-redis \
  --size 1 \
  --region us-central1 \
  --redis-version redis_6_x
```

## 监控和日志

### Prometheus 和 Grafana

1. **安装 Prometheus Operator**
```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace
```

2. **MCPSoc 监控配置**
```yaml
# mcpsoc-servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mcpsoc-metrics
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: mcpsoc-host
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
```

3. **Grafana Dashboard**
```json
{
  "dashboard": {
    "title": "MCPSoc Monitoring",
    "panels": [
      {
        "title": "Query Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, mcpsoc_query_duration_seconds_bucket)"
          }
        ]
      },
      {
        "title": "MCP Server Health",
        "type": "stat",
        "targets": [
          {
            "expr": "mcpsoc_mcp_servers_healthy_total"
          }
        ]
      }
    ]
  }
}
```

### ELK Stack 日志聚合

1. **部署 Elasticsearch**
```yaml
apiVersion: elasticsearch.k8s.elastic.co/v1
kind: Elasticsearch
metadata:
  name: mcpsoc-logs
spec:
  version: 8.5.0
  nodeSets:
  - name: default
    count: 3
    config:
      node.store.allow_mmap: false
```

2. **配置 Logstash**
```ruby
# logstash.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [kubernetes][container][name] == "mcpsoc-host" {
    json {
      source => "message"
    }
    date {
      match => [ "timestamp", "ISO8601" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "mcpsoc-logs-%{+YYYY.MM.dd}"
  }
}
```

## 安全配置

### TLS/SSL 配置

1. **使用 cert-manager 自动管理证书**
```bash
# 安装 cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# 创建 ClusterIssuer
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

### 网络策略

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcpsoc-network-policy
  namespace: mcpsoc
spec:
  podSelector:
    matchLabels:
      app: mcpsoc-host
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgresql
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
```

### RBAC 配置

```yaml
# rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mcpsoc-serviceaccount
  namespace: mcpsoc
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mcpsoc-role
  namespace: mcpsoc
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: mcpsoc-rolebinding
  namespace: mcpsoc
subjects:
- kind: ServiceAccount
  name: mcpsoc-serviceaccount
  namespace: mcpsoc
roleRef:
  kind: Role
  name: mcpsoc-role
  apiGroup: rbac.authorization.k8s.io
```

## 备份和恢复

### 数据库备份

```bash
# PostgreSQL 备份
kubectl exec deployment/postgresql -n mcpsoc -- pg_dump -U mcpsoc mcpsoc > backup-$(date +%Y%m%d).sql

# 定时备份 CronJob
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgresql-backup
  namespace: mcpsoc
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: postgres-backup
            image: postgres:14
            command:
            - /bin/bash
            - -c
            - |
              pg_dump -h postgresql -U mcpsoc mcpsoc | gzip > /backup/mcpsoc-backup-\$(date +%Y%m%d_%H%M%S).sql.gz
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: mcpsoc-secrets
                  key: database-password
            volumeMounts:
            - name: backup-storage
              mountPath: /backup
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
EOF
```

### 灾难恢复

1. **跨区域备份**
2. **数据同步策略**
3. **快速恢复流程**

## 性能优化

### 资源限制

```yaml
resources:
  requests:
    memory: "1Gi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "1"
```

### 水平自动扩展

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mcpsoc-host-hpa
  namespace: mcpsoc
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mcpsoc-host
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## 故障排查

### 常见问题

1. **Pod 无法启动**
```bash
kubectl describe pod <pod-name> -n mcpsoc
kubectl logs <pod-name> -n mcpsoc
```

2. **数据库连接失败**
```bash
kubectl exec -it deployment/mcpsoc-host -n mcpsoc -- nc -zv postgresql 5432
```

3. **服务不可访问**
```bash
kubectl get ingress -n mcpsoc
kubectl describe ingress mcpsoc-ingress -n mcpsoc
```

### 调试命令

```bash
# 查看所有资源
kubectl get all -n mcpsoc

# 查看事件
kubectl get events -n mcpsoc --sort-by='.lastTimestamp'

# 进入容器调试
kubectl exec -it deployment/mcpsoc-host -n mcpsoc -- /bin/bash

# 查看日志
kubectl logs -f deployment/mcpsoc-host -n mcpsoc

# 端口转发调试
kubectl port-forward service/mcpsoc-host 8080:8080 -n mcpsoc
```

这份部署指南提供了从开发测试到生产部署的完整方案，帮助用户根据具体需求选择合适的部署方式。