# Demo Backend

最小演示后端，用来演示：

1. Android app 调用 `Leona.sense()`
2. app 拿到 BoxId
3. app 把 BoxId 发给自己的业务后端
4. 业务后端再调用 Leona `/v1/verdict`
5. 验证 Leona 返回的 verdict 响应签名
6. 根据 risk 做 allow / challenge / deny
7. 给 Android sample 提供本地 `/v1/mobile-config`，验证 canonicalDeviceId /
   disabledSignals / disableCollectionWindowMs 收敛链路

---

## 启动

```bash
cd /Users/a/back/Game/cq/demo-backend
LEONA_BASE_URL=http://localhost:8080 \
LEONA_SECRET_KEY=your-secret-key \
go run .
```

默认监听：

- `http://localhost:8090`

---

## 接口

### Health

```bash
curl http://localhost:8090/health
```

### Demo verdict

```bash
curl -X POST http://localhost:8090/demo/verdict \
  -H 'Content-Type: application/json' \
  -d '{"boxId":"01HKF3XAQ8M9X1ZY5PQ123"}'
```

示例响应：

```json
{
  "boxId": "01HKF3XAQ8M9X1ZY5PQ123",
  "decision": "challenge",
  "riskLevel": "MEDIUM",
  "riskScore": 32,
  "honeypotSuggested": false
}
```

### Mobile config

```bash
curl http://localhost:8090/v1/mobile-config \
  -H 'X-Leona-Tenant: sample-tenant' \
  -H 'X-Leona-App-Id: sample-app' \
  -H 'X-Leona-Device-Id: Tdevice-1' \
  -H 'X-Leona-Install-Id: install-1' \
  -H 'X-Leona-Fingerprint: fingerprint-1'
```

示例响应：

```json
{
  "disabledSignals": ["androidId"],
  "disableCollectionWindowMs": 120000,
  "canonicalDeviceId": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a",
  "device": {
    "canonicalDeviceId": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a",
    "deviceId": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a",
    "id": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a"
  },
  "identity": {
    "canonicalDeviceId": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a",
    "deviceId": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a"
  },
  "deviceIdentity": {
    "canonicalDeviceId": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a",
    "deviceId": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a",
    "resolvedDeviceId": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a"
  }
}
```

---

## Canonical device store 规则

默认规则：

- 若设置 `DEMO_CLOUD_CANONICAL_DEVICE_ID`，直接固定返回该 canonical id
- 若请求已带 `X-Leona-Canonical-Device-Id`，优先接受，并回填到本地 store 的全部命中维度
- 否则按优先级查本地 store：
  1. `fingerprint`
  2. `deviceId`
  3. `tenant + appId + installId`
- 一旦任一维度命中，会把 canonical 回填到其它可用维度，保证后续降级请求仍稳定
- 若 store 没命中，则基于上述字段派生一个 `L...`，并持久化到本地 store
- fingerprint 与 deviceId 是设备级映射，跨 tenant/app 共享；installId 仍按 tenant/app 隔离

默认 store 路径：

- macOS / Linux: `${TMPDIR:-/tmp}/leona-demo-cloud-store.json`

当前 store 文件是结构化 JSON：

```json
{
  "version": 1,
  "records": [
    {
      "tenantId": "sample-tenant",
      "appId": "sample-app",
      "lookupKind": "fp",
      "lookupValue": "fingerprint-1",
      "canonicalDeviceId": "L7d7f0f2a4d0db4c0a2d8e6d2c9e0f0a",
      "source": "derived",
      "createdAt": "2026-04-24T12:00:00Z",
      "updatedAt": "2026-04-24T12:00:00Z"
    }
  ]
}
```

兼容性：

- 老的扁平 `map[string]string` store 会在读取时自动迁移到内存结构
- 下一次写回时会落成新的 `version + records` 格式

---

## 环境变量

- `DEMO_BACKEND_ADDR`：监听地址，默认 `:8090`
- `LEONA_BASE_URL`：Leona gateway 地址，默认 `http://localhost:8080`
- `LEONA_SECRET_KEY`：租户 secret key，**必填**
- `DEMO_CLOUD_DISABLED_SIGNALS`：mobile-config 下发的 disabled signals，默认 `androidId`
- `DEMO_CLOUD_DISABLE_COLLECTION_WINDOW_MS`：mobile-config 下发的 collection window，默认 `120000`
- `DEMO_CLOUD_CANONICAL_DEVICE_ID`：若设置则固定返回该 canonical id；否则按请求头稳定解析
- `DEMO_CLOUD_STORE_PATH`：canonical store 持久化文件路径；默认写入系统临时目录
