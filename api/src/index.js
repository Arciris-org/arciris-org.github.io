const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('rate-limiter-flexible');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com`
});

const db = admin.firestore();
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://arciris-os.github.io', 'https://www.arciris-os.github.io'] 
    : ['http://localhost:3000', 'http://localhost:8080'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const rateLimiter = new rateLimit.RateLimiterMemory({
  keyGenerator: (req) => req.ip,
  points: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  duration: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900, // 15分
});

const rateLimitMiddleware = async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    res.status(429).json({
      error: 'Too Many Requests',
      message: 'レート制限に達しました。しばらく待ってから再試行してください。',
      retryAfter: Math.round(rejRes.msBeforeNext / 1000)
    });
  }
};

app.use(rateLimitMiddleware);

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userDoc = await db.collection('users').doc(decoded.userId).get();
    
    if (!userDoc.exists) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = { id: decoded.userId, ...userDoc.data() };
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

const hashPassword = async (password) => {
  return await bcrypt.hash(password, 12);
};

const verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// JWTトークン生成
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { userId, type: 'access' },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
  );

  const refreshToken = jwt.sign(
    { userId, type: 'refresh' },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );

  return { accessToken, refreshToken };
};

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'ArcID API'
  });
});

// ==================== 認証API ====================

// ユーザー登録
app.post('/api/auth/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/),
  body('username').isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/),
  body('displayName').isLength({ min: 1, max: 50 })
], handleValidationErrors, async (req, res) => {
  try {
    const { email, password, username, displayName } = req.body;

    const existingUser = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (!existingUser.empty) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const existingUsername = await db.collection('users')
      .where('username', '==', username)
      .get();

    if (!existingUsername.empty) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const userId = uuidv4();
    const hashedPassword = await hashPassword(password);
    const now = new Date();

    const userData = {
      userId,
      email,
      username,
      displayName,
      password: hashedPassword,
      createdAt: now,
      updatedAt: now,
      isActive: true,
      settings: {
        notifications: true,
        betaUpdates: false,
        cloudSync: true
      },
      profile: {
        avatar: null,
        bio: '',
        timezone: 'Asia/Tokyo'
      }
    };

    await db.collection('users').doc(userId).set(userData);

    const tokens = generateTokens(userId);

    const { password: _, ...userResponse } = userData;

    res.status(201).json({
      message: 'User registered successfully',
      user: userResponse,
      tokens
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ユーザーログイン
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 1 })
], handleValidationErrors, async (req, res) => {
  try {
    const { email, password } = req.body;

    const userQuery = await db.collection('users')
      .where('email', '==', email)
      .limit(1)
      .get();

    if (userQuery.empty) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const userDoc = userQuery.docs[0];
    const userData = userDoc.data();

    if (!userData.isActive) {
      return res.status(401).json({ error: 'Account is deactivated' });
    }

    const isValidPassword = await verifyPassword(password, userData.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await db.collection('users').doc(userData.userId).update({
      lastLoginAt: new Date(),
      updatedAt: new Date()
    });

    const tokens = generateTokens(userData.userId);

    const { password: _, ...userResponse } = userData;

    res.json({
      message: 'Login successful',
      user: userResponse,
      tokens
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// トークンリフレッシュ
app.post('/api/auth/refresh', [
  body('refreshToken').isLength({ min: 1 })
], handleValidationErrors, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    
    if (decoded.type !== 'refresh') {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const userDoc = await db.collection('users').doc(decoded.userId).get();
    if (!userDoc.exists) {
      return res.status(401).json({ error: 'User not found' });
    }

    const tokens = generateTokens(decoded.userId);
    
    res.json({
      message: 'Token refreshed successfully',
      tokens
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// ログアウト
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    res.json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== ユーザー管理API ====================

app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { password, ...userProfile } = req.user;
    res.json({
      user: userProfile
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/user/profile', authenticateToken, [
  body('displayName').optional().isLength({ min: 1, max: 50 }),
  body('profile.bio').optional().isLength({ max: 500 }),
  body('profile.timezone').optional().isLength({ min: 1 }),
  body('settings.notifications').optional().isBoolean(),
  body('settings.betaUpdates').optional().isBoolean(),
  body('settings.cloudSync').optional().isBoolean()
], handleValidationErrors, async (req, res) => {
  try {
    const allowedFields = ['displayName', 'profile', 'settings'];
    const updates = {};
    
    Object.keys(req.body).forEach(key => {
      if (allowedFields.includes(key)) {
        if (key === 'profile' || key === 'settings') {
          updates[key] = { ...req.user[key], ...req.body[key] };
        } else {
          updates[key] = req.body[key];
        }
      }
    });

    updates.updatedAt = new Date();

    await db.collection('users').doc(req.user.userId).update(updates);

    res.json({
      message: 'Profile updated successfully',
      user: { ...req.user, ...updates }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/user/password', authenticateToken, [
  body('currentPassword').isLength({ min: 1 }),
  body('newPassword').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
], handleValidationErrors, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const isValidPassword = await verifyPassword(currentPassword, req.user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    const hashedNewPassword = await hashPassword(newPassword);

    await db.collection('users').doc(req.user.userId).update({
      password: hashedNewPassword,
      updatedAt: new Date()
    });

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Password update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 設定同期API ====================

app.get('/api/sync/settings', authenticateToken, async (req, res) => {
  try {
    const settingsDoc = await db.collection('userSettings').doc(req.user.userId).get();
    
    if (!settingsDoc.exists) {
      return res.json({
        settings: {
          dock: {},
          theme: {},
          apps: {},
          desktop: {}
        }
      });
    }

    res.json({
      settings: settingsDoc.data().settings || {}
    });
  } catch (error) {
    console.error('Settings fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/sync/settings', authenticateToken, [
  body('settings').isObject()
], handleValidationErrors, async (req, res) => {
  try {
    const { settings } = req.body;
    const now = new Date();

    await db.collection('userSettings').doc(req.user.userId).set({
      userId: req.user.userId,
      settings,
      lastSyncAt: now,
      updatedAt: now
    }, { merge: true });

    res.json({
      message: 'Settings synced successfully',
      lastSyncAt: now
    });
  } catch (error) {
    console.error('Settings sync error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/sync/settings', authenticateToken, [
  body('settings').isObject()
], handleValidationErrors, async (req, res) => {
  try {
    const { settings } = req.body;
    const now = new Date();

    const settingsDoc = await db.collection('userSettings').doc(req.user.userId).get();
    const currentSettings = settingsDoc.exists ? settingsDoc.data().settings || {} : {};

    const mergedSettings = { ...currentSettings, ...settings };

    await db.collection('userSettings').doc(req.user.userId).set({
      userId: req.user.userId,
      settings: mergedSettings,
      lastSyncAt: now,
      updatedAt: now
    }, { merge: true });

    res.json({
      message: 'Settings updated successfully',
      settings: mergedSettings,
      lastSyncAt: now
    });
  } catch (error) {
    console.error('Settings update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 端末管理API ====================

app.post('/api/devices', authenticateToken, [
  body('deviceName').isLength({ min: 1, max: 100 }),
  body('deviceType').isIn(['desktop', 'laptop', 'mobile', 'tablet']),
  body('os').isLength({ min: 1, max: 50 }),
  body('browser').optional().isLength({ max: 100 }),
  body('fingerprint').isLength({ min: 10, max: 200 })
], handleValidationErrors, async (req, res) => {
  try {
    const { deviceName, deviceType, os, browser, fingerprint } = req.body;
    const deviceId = uuidv4();
    const now = new Date();

    const existingDevice = await db.collection('devices')
      .where('userId', '==', req.user.userId)
      .where('fingerprint', '==', fingerprint)
      .get();

    if (!existingDevice.empty) {
      return res.status(409).json({ error: 'Device already registered' });
    }

    const deviceData = {
      deviceId,
      userId: req.user.userId,
      deviceName,
      deviceType,
      os,
      browser: browser || null,
      fingerprint,
      isActive: true,
      isTrusted: false, // 管理者が手動で承認
      createdAt: now,
      lastSeenAt: now,
      location: null,
      settings: {
        allowRemoteAccess: true,
        allowDataSync: true
      }
    };

    await db.collection('devices').doc(deviceId).set(deviceData);

    res.status(201).json({
      message: 'Device registered successfully',
      device: deviceData
    });
  } catch (error) {
    console.error('Device registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/devices', authenticateToken, async (req, res) => {
  try {
    const devicesQuery = await db.collection('devices')
      .where('userId', '==', req.user.userId)
      .orderBy('lastSeenAt', 'desc')
      .get();

    const devices = devicesQuery.docs.map(doc => doc.data());

    res.json({
      devices
    });
  } catch (error) {
    console.error('Devices fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/devices/:deviceId', authenticateToken, async (req, res) => {
  try {
    const { deviceId } = req.params;

    const deviceDoc = await db.collection('devices').doc(deviceId).get();
    
    if (!deviceDoc.exists) {
      return res.status(404).json({ error: 'Device not found' });
    }

    const deviceData = deviceDoc.data();
    
    if (deviceData.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    await db.collection('devices').doc(deviceId).delete();

    res.json({
      message: 'Device deleted successfully'
    });
  } catch (error) {
    console.error('Device deletion error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 改ざんログAPI ====================

app.post('/api/security/tamper-logs', authenticateToken, [
  body('deviceId').isUUID(),
  body('logLevel').isIn(['info', 'warning', 'critical']),
  body('eventType').isLength({ min: 1, max: 100 }),
  body('details').isObject(),
  body('timestamp').isISO8601()
], handleValidationErrors, async (req, res) => {
  try {
    const { deviceId, logLevel, eventType, details, timestamp } = req.body;
    const logId = uuidv4();
    const now = new Date();

    const deviceDoc = await db.collection('devices').doc(deviceId).get();
    if (!deviceDoc.exists || deviceDoc.data().userId !== req.user.userId) {
      return res.status(403).json({ error: 'Device access denied' });
    }

    const logData = {
      logId,
      userId: req.user.userId,
      deviceId,
      logLevel,
      eventType,
      details,
      timestamp: new Date(timestamp),
      createdAt: now,
      isResolved: false
    };

    await db.collection('tamperLogs').doc(logId).set(logData);

    if (logLevel === 'critical') {
      await db.collection('notifications').add({
        userId: req.user.userId,
        type: 'security_alert',
        title: 'セキュリティ警告',
        message: `端末 ${deviceDoc.data().deviceName} で重要なセキュリティイベントが検出されました: ${eventType}`,
        data: { logId, deviceId },
        isRead: false,
        createdAt: now
      });
    }

    res.status(201).json({
      message: 'Tamper log saved successfully',
      log: logData
    });
  } catch (error) {
    console.error('Tamper log save error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/security/tamper-logs', authenticateToken, async (req, res) => {
  try {
    const { deviceId, level, limit = 50, offset = 0 } = req.query;

    let query = db.collection('tamperLogs')
      .where('userId', '==', req.user.userId);

    if (deviceId) {
      query = query.where('deviceId', '==', deviceId);
    }

    if (level) {
      query = query.where('logLevel', '==', level);
    }

    query = query.orderBy('timestamp', 'desc')
      .limit(parseInt(limit))
      .offset(parseInt(offset));

    const logsQuery = await query.get();
    const logs = logsQuery.docs.map(doc => doc.data());

    res.json({
      logs,
      total: logs.length,
      hasMore: logs.length === parseInt(limit)
    });
  } catch (error) {
    console.error('Tamper logs fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== リモート操作API ====================

app.post('/api/remote/block/:deviceId', authenticateToken, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { reason = 'User initiated block' } = req.body;

    const deviceDoc = await db.collection('devices').doc(deviceId).get();
    if (!deviceDoc.exists || deviceDoc.data().userId !== req.user.userId) {
      return res.status(403).json({ error: 'Device access denied' });
    }

    const now = new Date();
    const commandId = uuidv4();

    const commandData = {
      commandId,
      userId: req.user.userId,
      deviceId,
      type: 'block',
      reason,
      status: 'pending',
      createdAt: now,
      executedAt: null
    };

    await db.collection('remoteCommands').doc(commandId).set(commandData);

    await db.collection('devices').doc(deviceId).update({
      isBlocked: true,
      blockedAt: now,
      blockReason: reason,
      updatedAt: now
    });

    res.json({
      message: 'Device block command sent successfully',
      command: commandData
    });
  } catch (error) {
    console.error('Remote block error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/remote/rollback/:deviceId', authenticateToken, [
  body('backupId').optional().isLength({ min: 1 }),
  body('reason').optional().isLength({ max: 500 })
], handleValidationErrors, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { backupId, reason = 'User initiated rollback' } = req.body;

    const deviceDoc = await db.collection('devices').doc(deviceId).get();
    if (!deviceDoc.exists || deviceDoc.data().userId !== req.user.userId) {
      return res.status(403).json({ error: 'Device access denied' });
    }

    const now = new Date();
    const commandId = uuidv4();

    const commandData = {
      commandId,
      userId: req.user.userId,
      deviceId,
      type: 'rollback',
      backupId: backupId || 'latest',
      reason,
      status: 'pending',
      createdAt: now,
      executedAt: null
    };

    await db.collection('remoteCommands').doc(commandId).set(commandData);

    res.json({
      message: 'Device rollback command sent successfully',
      command: commandData
    });
  } catch (error) {
    console.error('Remote rollback error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/remote/commands', authenticateToken, async (req, res) => {
  try {
    const { deviceId, status, limit = 20 } = req.query;

    let query = db.collection('remoteCommands')
      .where('userId', '==', req.user.userId);

    if (deviceId) {
      query = query.where('deviceId', '==', deviceId);
    }

    if (status) {
      query = query.where('status', '==', status);
    }

    query = query.orderBy('createdAt', 'desc').limit(parseInt(limit));

    const commandsQuery = await query.get();
    const commands = commandsQuery.docs.map(doc => doc.data());

    res.json({
      commands
    });
  } catch (error) {
    console.error('Remote commands fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 通知API ====================

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { unreadOnly = false, limit = 50, offset = 0 } = req.query;

    let query = db.collection('notifications')
      .where('userId', '==', req.user.userId);

    if (unreadOnly === 'true') {
      query = query.where('isRead', '==', false);
    }

    query = query.orderBy('createdAt', 'desc')
      .limit(parseInt(limit))
      .offset(parseInt(offset));

    const notificationsQuery = await query.get();
    const notifications = notificationsQuery.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      notifications,
      total: notifications.length,
      hasMore: notifications.length === parseInt(limit)
    });
  } catch (error) {
    console.error('Notifications fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/notifications/:notificationId/read', authenticateToken, async (req, res) => {
  try {
    const { notificationId } = req.params;

    const notificationDoc = await db.collection('notifications').doc(notificationId).get();
    
    if (!notificationDoc.exists) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    const notificationData = notificationDoc.data();
    
    if (notificationData.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    await db.collection('notifications').doc(notificationId).update({
      isRead: true,
      readAt: new Date()
    });

    res.json({
      message: 'Notification marked as read'
    });
  } catch (error) {
    console.error('Notification update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const batch = db.batch();
    const now = new Date();

    const unreadNotifications = await db.collection('notifications')
      .where('userId', '==', req.user.userId)
      .where('isRead', '==', false)
      .get();

    unreadNotifications.docs.forEach(doc => {
      batch.update(doc.ref, {
        isRead: true,
        readAt: now
      });
    });

    await batch.commit();

    res.json({
      message: 'All notifications marked as read',
      updatedCount: unreadNotifications.size
    });
  } catch (error) {
    console.error('Notifications bulk update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== エラーハンドリング ====================

app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested endpoint does not exist'
  });
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred' 
      : error.message
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 ArcID API Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 Security features enabled`);
});

module.exports = app;