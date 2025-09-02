# ArcID API Documentation

ArcIDとクラウドサービスのAPI

## 概要

ArcIDは、ArcirisOSの認証システムとクラウドサービスを提供するAPI

### 主な機能
- ユーザー認証（登録/ログイン/トークンリフレッシュ）
- プロフィール管理
- クラウド設定同期
- 端末管理
- セキュリティログ（改ざん検知ログ）
- リモート操作（ブロック/ロールバック）
- 通知システム

## ベースURL
- 開発環境: `http://localhost:3000/api`
- 本番環境: `https://id.arciris.org/api`

## 認証
JWT（JSON Web Token）を使用した認証システム。

### ヘッダー形式
```
Authorization: Bearer <access_token>
```

### トークンの種類
- **Access Token**: API呼び出し用（24時間有効）
- **Refresh Token**: Access Token更新用（7日間有効）

## エンドポイント一覧

### 🔐 認証API

#### POST /auth/register
ユーザー登録

**リクエスト:**
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd",
  "username": "username123",
  "displayName": "表示名"
}
```

**レスポンス:**
```json
{
  "message": "User registered successfully",
  "user": {
    "userId": "uuid",
    "email": "user@example.com",
    "username": "username123",
    "displayName": "表示名",
    "createdAt": "2025-09-02T00:00:00.000Z",
    "settings": {
      "notifications": true,
      "betaUpdates": false,
      "cloudSync": true
    }
  },
  "tokens": {
    "accessToken": "jwt_token",
    "refreshToken": "refresh_token"
  }
}
```

#### POST /auth/login
ユーザーログイン

**リクエスト:**
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd"
}
```

#### POST /auth/refresh
トークンリフレッシュ

**リクエスト:**
```json
{
  "refreshToken": "refresh_token"
}
```

#### POST /auth/logout
ログアウト（認証必須）

### 👤 ユーザー管理API

#### GET /user/profile
ユーザー情報取得（認証必須）

**レスポンス:**
```json
{
  "user": {
    "userId": "uuid",
    "email": "user@example.com",
    "username": "username123",
    "displayName": "表示名",
    "profile": {
      "avatar": null,
      "bio": "",
      "timezone": "Asia/Tokyo"
    },
    "settings": {
      "notifications": true,
      "betaUpdates": false,
      "cloudSync": true
    }
  }
}
```

#### PATCH /user/profile
ユーザー情報更新（認証必須）

**リクエスト:**
```json
{
  "displayName": "新しい表示名",
  "profile": {
    "bio": "自己紹介文",
    "timezone": "UTC"
  },
  "settings": {
    "notifications": false,
    "betaUpdates": true
  }
}
```

#### PATCH /user/password
パスワード変更（認証必須）

**リクエスト:**
```json
{
  "currentPassword": "現在のパスワード",
  "newPassword": "新しいパスワード"
}
```

### ☁️ 設定同期API

#### GET /sync/settings
設定取得（認証必須）

**レスポンス:**
```json
{
  "settings": {
    "dock": {
      "position": "bottom",
      "autohide": false,
      "apps": ["app1", "app2"]
    },
    "theme": {
      "mode": "dark",
      "accentColor": "#007acc"
    },
    "apps": {
      "defaultApps": {}
    },
    "desktop": {
      "wallpaper": "wallpaper1.png"
    }
  }
}
```

#### POST /sync/settings
設定同期（保存）（認証必須）

**リクエスト:**
```json
{
  "settings": {
    "dock": {
      "position": "bottom",
      "autohide": false
    },
    "theme": {
      "mode": "dark"
    }
  }
}
```

#### PATCH /sync/settings
設定部分更新（認証必須）

### 📱 端末管理API

#### POST /devices
端末登録（認証必須）

**リクエスト:**
```json
{
  "deviceName": "My Laptop",
  "deviceType": "laptop",
  "os": "ArcirisOS 1.0",
  "browser": "Chrome 118",
  "fingerprint": "unique_device_fingerprint"
}
```

#### GET /devices
端末一覧取得（認証必須）

**レスポンス:**
```json
{
  "devices": [
    {
      "deviceId": "uuid",
      "deviceName": "My Laptop",
      "deviceType": "laptop",
      "os": "ArcirisOS 1.0",
      "isActive": true,
      "isTrusted": false,
      "lastSeenAt": "2025-09-02T00:00:00.000Z"
    }
  ]
}
```

#### DELETE /devices/:deviceId
端末削除（認証必須）

### 🔒 セキュリティログAPI

#### POST /security/tamper-logs
改ざんログ保存（認証必須）

**リクエスト:**
```json
{
  "deviceId": "device_uuid",
  "logLevel": "critical",
  "eventType": "boot_integrity_check_failed",
  "details": {
    "checksum": "expected_vs_actual",
    "affectedFiles": ["/boot/kernel"]
  },
  "timestamp": "2025-09-02T00:00:00.000Z"
}
```

#### GET /security/tamper-logs
改ざんログ取得（認証必須）

**クエリパラメータ:**
- `deviceId`: 特定デバイスのログのみ
- `level`: ログレベルフィルタ（info/warning/critical）
- `limit`: 取得件数（デフォルト: 50）
- `offset`: オフセット（デフォルト: 0）

### 🎮 リモート操作API

#### POST /remote/block/:deviceId
リモートブロック（認証必須）

**リクエスト:**
```json
{
  "reason": "端末紛失のため"
}
```

#### POST /remote/rollback/:deviceId
リモートロールバック（認証必須）

**リクエスト:**
```json
{
  "backupId": "backup_uuid",
  "reason": "マルウェア感染のため"
}
```

#### GET /remote/commands
リモートコマンド状態取得（認証必須）

**クエリパラメータ:**
- `deviceId`: 特定デバイスのコマンドのみ
- `status`: コマンド状態（pending/executed/failed）
- `limit`: 取得件数（デフォルト: 20）

### 🔔 通知API

#### GET /notifications
通知取得（認証必須）

**クエリパラメータ:**
- `unreadOnly`: 未読のみ（true/false）
- `limit`: 取得件数（デフォルト: 50）
- `offset`: オフセット（デフォルト: 0）

**レスポンス:**
```json
{
  "notifications": [
    {
      "id": "notification_id",
      "type": "security_alert",
      "title": "セキュリティ警告",
      "message": "端末で重要なセキュリティイベントが検出されました",
      "isRead": false,
      "createdAt": "2025-09-02T00:00:00.000Z"
    }
  ]
}
```

#### PATCH /notifications/:notificationId/read
通知既読マーク（認証必須）

#### PATCH /notifications/read-all
全通知既読マーク（認証必須）

## エラーレスポンス

### 共通エラー形式
```json
{
  "error": "Error Type",
  "message": "エラーメッセージ",
  "details": [] // バリデーションエラーの詳細（該当する場合）
}
```

### HTTPステータスコード
- `200`: 成功
- `201`: 作成成功
- `400`: 不正なリクエスト
- `401`: 認証が必要
- `403`: アクセス権限なし
- `404`: リソースが見つからない
- `409`: リソースの競合
- `429`: レート制限
- `500`: サーバーエラー

## セキュリティ機能

### パスワード要件
- 最低8文字
- 大文字・小文字・数字・特殊文字を含む

### レート制限
- 15分間に100リクエストまで
- IPアドレス単位で制限

### セキュリティヘッダー
- HSTS有効
- Content Security Policy設定済み
- XSS Protection有効

### データ暗号化
- パスワードはbcryptでハッシュ化
- JWTトークンでセッション管理
- HTTPS通信必須（本番環境）

## 使用例

### 基本的な認証フロー

1. **ユーザー登録**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd",
    "username": "myusername",
    "displayName": "My Name"
  }'
```

2. **ログイン**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd"
  }'
```

3. **認証が必要なAPI呼び出し**
```bash
curl -X GET http://localhost:3000/api/user/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 開発環境セットアップ

1. **環境変数設定**
   `.env`ファイルにFirebase設定とJWT秘密鍵を設定

2. **依存関係インストール**
   ```bash
   npm install
   ```

3. **開発サーバー起動**
   ```bash
   npm run dev
   ```

4. **ヘルスチェック**
   ```bash
   curl http://localhost:3000/api/health
   ```
