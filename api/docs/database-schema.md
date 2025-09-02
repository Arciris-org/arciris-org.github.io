# ArcID Firestore データベース設計

## コレクション構造

### 👤 users
ユーザー基本情報とアカウント設定

```javascript
{
  userId: "uuid",
  email: "user@example.com",
  username: "username123",
  displayName: "表示名",
  password: "bcrypt_hashed_password",
  createdAt: "timestamp",
  updatedAt: "timestamp",
  lastLoginAt: "timestamp",
  isActive: true,
  settings: {
    notifications: true,
    betaUpdates: false,
    cloudSync: true
  },
  profile: {
    avatar: "avatar_url or null",
    bio: "自己紹介文",
    timezone: "Asia/Tokyo"
  }
}
```

**インデックス:**
- email (unique)
- username (unique)
- isActive

### ☁️ userSettings
ユーザーのクラウド同期設定

```javascript
{
  userId: "user_uuid",
  settings: {
    dock: {
      position: "bottom", // "top", "left", "right"
      autohide: false,
      size: "medium", // "small", "medium", "large"
      apps: ["app1", "app2", "app3"], // アプリID配列
      theme: "default"
    },
    theme: {
      mode: "dark", // "light", "dark", "auto"
      accentColor: "#007acc",
      wallpaper: "wallpaper1.png",
      customCSS: "/* カスタムCSS */"
    },
    apps: {
      defaultApps: {
        browser: "arcbrowser",
        fileManager: "arcfiles",
        textEditor: "arcnote"
      },
      appPositions: {
        "app1": { x: 100, y: 200 },
        "app2": { x: 300, y: 400 }
      }
    },
    desktop: {
      showIcons: true,
      iconSize: "medium",
      gridSnap: true,
      widgets: [
        {
          id: "weather",
          position: { x: 10, y: 10 },
          size: { width: 200, height: 100 }
        }
      ]
    },
    system: {
      startupApps: ["app1", "app2"],
      notifications: {
        enabled: true,
        position: "top-right",
        timeout: 5000
      },
      keyboard: {
        layout: "jp",
        shortcuts: {
          "ctrl+t": "new_tab",
          "ctrl+shift+t": "restore_tab"
        }
      }
    }
  },
  lastSyncAt: "timestamp",
  updatedAt: "timestamp"
}
```

**インデックス:**
- userId

### 📱 devices
登録済み端末情報

```javascript
{
  deviceId: "uuid",
  userId: "user_uuid",
  deviceName: "My Laptop",
  deviceType: "laptop", // "desktop", "laptop", "mobile", "tablet"
  os: "ArcirisOS 1.0",
  browser: "Chrome 118.0.0.0",
  fingerprint: "unique_device_fingerprint", // ハードウェア識別子
  isActive: true,
  isTrusted: false, // 管理者による承認フラグ
  isBlocked: false,
  blockReason: null,
  blockedAt: null,
  createdAt: "timestamp",
  lastSeenAt: "timestamp",
  updatedAt: "timestamp",
  location: {
    country: "Japan",
    city: "Tokyo",
    ip: "192.168.1.1" // ハッシュ化されたIP
  },
  settings: {
    allowRemoteAccess: true,
    allowDataSync: true,
    autoUpdate: true
  },
  hardware: {
    cpu: "Intel Core i7-12700H",
    memory: "16GB",
    storage: "512GB SSD",
    screen: "1920x1080"
  }
}
```

**インデックス:**
- userId
- fingerprint
- isActive
- isTrusted
- lastSeenAt

### 🔒 tamperLogs
改ざん検知ログ

```javascript
{
  logId: "uuid",
  userId: "user_uuid",
  deviceId: "device_uuid",
  logLevel: "critical", // "info", "warning", "critical"
  eventType: "boot_integrity_check_failed",
  details: {
    checksum: {
      expected: "sha256_hash",
      actual: "sha256_hash"
    },
    affectedFiles: [
      "/boot/kernel",
      "/boot/initrd"
    ],
    systemInfo: {
      bootTime: "2025-09-02T00:00:00.000Z",
      secureBootEnabled: true,
      tpmVersion: "2.0"
    }
  },
  timestamp: "timestamp", // イベント発生時刻
  createdAt: "timestamp", // ログ作成時刻
  isResolved: false,
  resolvedAt: null,
  resolvedBy: null, // ユーザーまたは自動解決
  resolutionNote: null
}
```

**インデックス:**
- userId
- deviceId
- logLevel
- timestamp
- isResolved

### 🎮 remoteCommands
リモート操作コマンド

```javascript
{
  commandId: "uuid",
  userId: "user_uuid",
  deviceId: "device_uuid",
  type: "block", // "block", "rollback", "wipe", "lock"
  reason: "端末紛失のため",
  status: "pending", // "pending", "sent", "executed", "failed", "timeout"
  createdAt: "timestamp",
  sentAt: null,
  executedAt: null,
  failedAt: null,
  parameters: {
    // ロールバック用
    backupId: "backup_uuid",
    targetDate: "2025-09-01T00:00:00.000Z",
    
    // ブロック用
    blockType: "full", // "full", "partial"
    allowEmergencyAccess: false,
    
    // ワイプ用
    wipeType: "secure", // "quick", "secure"
    keepSystemFiles: false
  },
  result: {
    success: true,
    message: "Command executed successfully",
    logs: ["Step 1: OK", "Step 2: OK"],
    error: null
  }
}
```

**インデックス:**
- userId
- deviceId
- type
- status
- createdAt

### 🔔 notifications
ユーザー通知

```javascript
{
  // ドキュメントIDは自動生成
  userId: "user_uuid",
  type: "security_alert", // "security_alert", "system_update", "device_activity", "sync_error"
  title: "セキュリティ警告",
  message: "端末 My Laptop で重要なセキュリティイベントが検出されました: boot_integrity_check_failed",
  data: {
    logId: "tamper_log_uuid",
    deviceId: "device_uuid",
    actionUrl: "/security/logs/tamper_log_uuid"
  },
  isRead: false,
  readAt: null,
  createdAt: "timestamp",
  expiresAt: "timestamp", // 自動削除日時
  priority: "high" // "low", "normal", "high", "urgent"
}
```

**インデックス:**
- userId
- type
- isRead
- createdAt
- priority

### 💾 backups
システムバックアップ情報

```javascript
{
  backupId: "uuid",
  userId: "user_uuid",
  deviceId: "device_uuid",
  type: "automatic", // "automatic", "manual", "pre_update"
  status: "completed", // "creating", "completed", "failed", "deleted"
  createdAt: "timestamp",
  completedAt: "timestamp",
  size: 1073741824, // バイト
  checksum: "sha256_hash",
  storageLocation: "gs://arcid-backups/user_uuid/backup_uuid.tar.gz",
  metadata: {
    osVersion: "ArcirisOS 1.0",
    kernelVersion: "6.1.0-arc",
    installedApps: ["app1", "app2"],
    userDataSize: 536870912,
    systemDataSize: 536870912
  },
  retention: {
    keepUntil: "timestamp",
    reason: "user_policy" // "user_policy", "compliance", "legal_hold"
  }
}
```

**インデックス:**
- userId
- deviceId
- type
- status
- createdAt

### 📊 analytics
使用統計とテレメトリ（オプトイン）

```javascript
{
  // ドキュメントIDは自動生成
  userId: "user_uuid",
  deviceId: "device_uuid",
  eventType: "app_launch", // "app_launch", "feature_usage", "error_report"
  eventData: {
    appId: "arcbrowser",
    duration: 3600000, // ミリ秒
    version: "1.0.0",
    features: ["tabs", "bookmarks"]
  },
  timestamp: "timestamp",
  sessionId: "session_uuid",
  isAnonymized: true // 個人特定不可能にする
}
```

**インデックス:**
- userId
- deviceId
- eventType
- timestamp

## セキュリティルール例

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // ユーザーは自分のデータのみアクセス可能
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    match /userSettings/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    match /devices/{deviceId} {
      allow read, write: if request.auth != null && 
        request.auth.uid == resource.data.userId;
    }
    
    match /tamperLogs/{logId} {
      allow read, write: if request.auth != null && 
        request.auth.uid == resource.data.userId;
    }
    
    match /remoteCommands/{commandId} {
      allow read, write: if request.auth != null && 
        request.auth.uid == resource.data.userId;
    }
    
    match /notifications/{notificationId} {
      allow read, write: if request.auth != null && 
        request.auth.uid == resource.data.userId;
    }
    
    match /backups/{backupId} {
      allow read, write: if request.auth != null && 
        request.auth.uid == resource.data.userId;
    }
    
    // 管理者のみアクセス可能
    match /analytics/{document} {
      allow read, write: if request.auth != null && 
        request.auth.token.admin == true;
    }
  }
}
```

## データ保持ポリシー

### 自動削除
- **notifications**: 30日後に自動削除
- **tamperLogs**: 解決済みログは1年後に削除
- **analytics**: 匿名化済みデータは2年後に削除

### ユーザー削除時
- **users**: 即座に削除
- **userSettings**: 即座に削除
- **devices**: 30日後に削除（復旧期間）
- **tamperLogs**: 匿名化して1年保持
- **notifications**: 即座に削除
- **backups**: 即座に削除

## パフォーマンス最適化

### 複合インデックス
```javascript
// デバイス別の最新改ざんログ
tamperLogs: [userId, deviceId, timestamp desc]

// 未読通知の優先度順
notifications: [userId, isRead, priority desc, createdAt desc]

// アクティブ端末の最終アクセス順
devices: [userId, isActive, lastSeenAt desc]
```

### キャッシュ戦略
- **userSettings**: Redis で30分キャッシュ
- **devices**: アクティブ端末リストを15分キャッシュ
- **notifications**: 未読数を5分キャッシュ
