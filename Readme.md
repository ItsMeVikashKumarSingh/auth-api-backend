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

### App Signature Verification API
- Verify user and send them server public key

### Store Security Questions and Answers
- Store user questions and answers 

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

### **1. Register API**
- **Endpoint**: `POST /api/register`
- **Purpose**: Registers a new user.
- **Request**:
```json
{
  "encryptedData": "BASE64_ENCRYPTED_PAYLOAD"
}
```
- **Decrypted Payload**:
```json
{
  "username": "plain_text_username",
  "password": "plain_text_password",
  "clientPublicKey": "HEX_PUBLIC_KEY"
}
```
- **Response**:
```json
{
  "encryptedData": "BASE64_ENCRYPTED_RESPONSE"
}
```
- **Decrypted Response**:
```json
{
  "message": "User registered successfully.",
  "backupKey": "BACKUP_KEY",
  "uuid": "USER_UUID"
}
```
- **Database Changes**:
  - **`reg_user` Collection**:
    ```json
    {
      "usernameHash": "HASHED_USERNAME",
      "uuid": "USER_UUID"
    }
    ```
  - **`users` Collection**:
    ```json
    {
      "uuid": "USER_UUID",
      "p_hash": "HASHED_PASSWORD",
      "b_code": "HASHED_BACKUP_KEY",
      "bio": "Default bio",
      "name": "Default name",
      "p_pic": "Default profile picture URL",
      "status": "active",
      "created_at": "TIMESTAMP",
      "last_login": null
    }
    ```

---

### **2. Login API**
- **Endpoint**: `POST /api/login`
- **Purpose**: Authenticates an existing user.
- **Request**:
```json
{
  "encryptedData": "BASE64_ENCRYPTED_PAYLOAD"
}
```
- **Decrypted Payload**:
```json
{
  "username": "plain_text_username",
  "password": "plain_text_password",
  "clientPublicKey": "HEX_PUBLIC_KEY"
}
```
- **Response**:
```json
{
  "encryptedData": "BASE64_ENCRYPTED_RESPONSE"
}
```
- **Decrypted Response**:
```json
{
  "message": "Login successful.",
  "token": "SESSION_TOKEN",
  "expires_at": "SESSION_EXPIRY_TIME",
  "uuid": "USER_UUID"
}
```
- **Database Changes**:
  - Updates `last_login` in the `users` collection.
  - Adds a new session in the `sessions` collection.

---

### **3. Store Security Questions and Answers**
- **Endpoint**: `POST /api/store-user-questions`
- **Purpose**: Stores the user's selected security questions and hashed answers.
- **Request**:
```json
{
  "encryptedData": "BASE64_ENCRYPTED_PAYLOAD"
}
```
- **Decrypted Payload**:
```json
{
  "uuid": "USER_UUID",
  "selectedQuestions": [0, 4, 7, 11, 20],
  "answers": ["plain_text_answer1", "plain_text_answer2", "plain_text_answer3"]
}
```
- **Response**:
```json
{
  "message": "Security questions stored successfully."
}
```
- **Database Changes**:
  - **`user_questions` Collection**:
    ```json
    {
      "uuid": "USER_UUID",
      "questions": [
        { "questionId": 0, "answerHash": "HASHED_ANSWER" },
        { "questionId": 4, "answerHash": "HASHED_ANSWER" },
        ...
      ]
    }
    ```

---

### **4. App Signature Verification API**
- **Endpoint**: `POST /api/getapi`
- **Purpose**: Verifies app signature and device unique ID.
- **Request**:
```json
{
  "signature": "PLAIN_TEXT_SIGNATURE",
  "deviceId": "DEVICE_UNIQUE_ID"
}
```
- **Response**:
  - If signature is valid:
    ```json
    {
      "encryptedData": "BASE64_ENCRYPTED_RESPONSE"
    }
    ```
    - **Decrypted Response**:
      ```json
      {
        "message": "App verified.",
        "serverPublicKey": "SERVER_PUBLIC_KEY"
      }
      ```
  - If signature is invalid:
    ```json
    {
      "error": "Unauthorized app. Please use the official app."
    }
    ```
- **Database Changes**:
  - Warnings are stored in the `ban` collection for unauthorized devices.
    ```json
    {
      "device": {
        "DEVICE_UNIQUE_ID": WARNING_COUNT
      }
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




Here’s a **copy-paste-friendly version** of the updated README.md:

---
