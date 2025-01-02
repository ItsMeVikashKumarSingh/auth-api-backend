# Secure Authentication System

This project implements a secure and robust authentication system with support for password-based login, two-factor authentication (2FA) using TOTP (Time-based One-Time Password), and backup mechanisms like security questions and backup keys.

## Features

### User Registration
- Secure password storage with Argon2.
- Unique username hashing for privacy.
- Encrypted communication for sensitive data.

### User Login
- Validation with deterministic username hashing.
- Support for multiple active sessions.
- Encrypted responses for added security.

### Forgot Password
- Backup key mechanism.
- Security questions mechanism.
- Third-party authenticator integration.

### Two-Factor Authentication
- Generate QR code for TOTP setup.
- Validate TOTP during login or operations.
- Encrypted responses for secure communication.

---

## Database Structure

### 1. `reg_user` (Index for Usernames)

| Field            | Description                  |
|-------------------|------------------------------|
| `{hashedUsername}` | Key for username hash (string) |
| `uuid`            | User's unique identifier (string) |

**Example Data:**
```json
{
  "hashedUsername": "hashed_value_of_username",
  "uuid": "1"
}
```

### 2. `users` (Main User Collection)

| Field       | Description                       |
|-------------|-----------------------------------|
| `u_hash`    | Username hash (string)           |
| `p_hash`    | Password hash (string)           |
| `b_code`    | Backup code hash (string)        |
| `created`   | Account creation timestamp (ISO) |
| `last_login`| Last login timestamp (ISO)       |
| `bio`       | Default bio                      |
| `name`      | Default name                     |
| `p_pic`     | Default profile picture          |
| `status`    | Account status (active, banned)  |

**Example Data:**
```json
{
  "u_hash": "hashed_value_of_username",
  "p_hash": "argon2_hash_of_password",
  "b_code": "deterministic_backup_code_hash",
  "created": "2024-01-01T10:00:00.000+05:30",
  "last_login": "2024-01-15T10:30:00.000+05:30",
  "bio": "This is a default bio.",
  "name": "Default Name",
  "p_pic": "https://example.com/default.jpg",
  "status": "active"
}
```

### 3. `sessions` (User Sessions)

| Field       | Description                |
|-------------|----------------------------|
| `{uuid}`    | Document ID mapped to user sessions |
| `sessionId` | Unique session ID          |
| `expires_at`| Expiry timestamp           |

**Example Data:**
```json
{
  "sessionId": {
    "token": "jwt_token",
    "expires_at": "2024-01-15T11:30:00.000+05:30"
  }
}
```

### 4. `logsDB` (MongoDB for Logs)

| Collection       | Description                      |
|------------------|----------------------------------|
| `register`       | Logs for registration operations |
| `login`          | Logs for login operations        |
| `ForgotPassword` | Logs for forgot password APIs    |
| `protected`      | Logs for protected operations    |

**Example Data:**
```json
{
  "timestamp": "2024-01-15T10:00:00+05:30",
  "message": "User registered successfully.",
  "data": {
    "uuid": "1",
    "username": "hashed_value"
  }
}
```

---

## API Details

### 1. Register API
**Endpoint:** `POST /api/register`

**Request:**
```json
{
  "encryptedData": "BASE64_ENCRYPTED_DATA"
}
```
**Decrypted Request:**
```json
{
  "username": "plain_username",
  "password": "plain_password",
  "clientPublicKey": "client_public_key"
}
```

**Response:**
```json
{
  "encryptedData": "BASE64_ENCRYPTED_RESPONSE"
}
```
**Decrypted Response:**
```json
{
  "message": "User registered successfully.",
  "backupCode": "plain_backup_code",
  "uuid": "1"
}
```

### 2. Login API
**Endpoint:** `POST /api/login`

**Request:**
```json
{
  "encryptedData": "BASE64_ENCRYPTED_DATA"
}
```
**Decrypted Request:**
```json
{
  "username": "plain_username",
  "password": "plain_password",
  "clientPublicKey": "client_public_key"
}
```

**Response:**
```json
{
  "encryptedData": "BASE64_ENCRYPTED_RESPONSE"
}
```
**Decrypted Response:**
```json
{
  "message": "Login successful.",
  "token": "jwt_token",
  "uuid": "1",
  "expires_at": "2024-01-15T11:30:00.000+05:30"
}
```

### 3. Generate Authenticator QR API
**Endpoint:** `POST /api/generate-qr`

**Request:**
```json
{
  "encryptedData": "BASE64_ENCRYPTED_DATA"
}
```
**Decrypted Request:**
```json
{
  "uuid": "1",
  "clientPublicKey": "client_public_key"
}
```

**Response:**
```json
{
  "encryptedData": "BASE64_ENCRYPTED_RESPONSE"
}
```
**Decrypted Response:**
```json
{
  "message": "QR code generated successfully.",
  "qrCodeUrl": "data:image/png;base64,..."
}
```

### 4. Enable Authenticator API
**Endpoint:** `POST /api/enable-authenticator`

**Request:**
```json
{
  "encryptedData": "BASE64_ENCRYPTED_DATA"
}
```
**Decrypted Request:**
```json
{
  "uuid": "1",
  "totpCode": "123456",
  "clientPublicKey": "client_public_key"
}
```

**Response:**
```json
{
  "encryptedData": "BASE64_ENCRYPTED_RESPONSE"
}
```
**Decrypted Response:**
```json
{
  "message": "Authenticator enabled successfully."
}
```

---

## Security Measures

### Argon2 for Password Hashing
- Provides strong resistance against brute-force attacks.

### Deterministic Hashing for Usernames and Backup Keys
- Ensures unique identifiers without storing plain text.

### TOTP Integration
- Adds a second layer of security.

### Encrypted Communication
- All sensitive data is encrypted using libsodium.

### Session Cleanup
- Removes expired sessions to maintain session hygiene.