# Robust NestJS Authentication API with 2FA

## About The Project

This project provides a secure, robust, and feature-complete backend service for user authentication and authorization, built with NestJS and Prisma. It goes beyond simple login/password mechanisms by implementing a full lifecycle for Time-Based One-Time Password (TOTP) Two-Factor Authentication (2FA), including secure setup, verification, and account recovery via backup codes.

The primary goal is to offer a production-ready foundation for any application requiring a high level of security.

## Key Features

This API includes a comprehensive set of features for modern authentication:

### User Authentication
- Secure user registration and password validation using bcryptjs

### JWT-Based Authorization
- Implements Access Tokens and Refresh Tokens using the RS256 algorithm
- Refresh tokens are securely handled via HttpOnly cookies

### Complete 2FA Lifecycle
- **Secure Enablement**: A QR code-based setup flow using otplib
- **Critical Confirmation Step**: A mandatory confirmation step prevents users from locking themselves out of their accounts
- **Encrypted Secret Storage**: 2FA secrets are encrypted (AES-256) at rest, never stored as plaintext
- **2FA Verification**: Logic to validate TOTP tokens during login

### Account Recovery Mechanism
- **Backup Code Generation**: Automatically generates a list of single-use backup codes upon successful 2FA confirmation
- **Secure Backup Code Storage**: Backup codes are hashed using bcryptjs before being stored
- **Login with Backup Code**: Allows users who have lost their authenticator device to regain access

### Clear API Communication
- Uses custom error codes (e.g., 2FA_REQUIRED) to provide unambiguous responses to the client, enabling a better user experience

## Tech Stack

- **Backend Framework**: NestJS
- **ORM**: Prisma
- **Database**: PostgreSQL
- **Language**: TypeScript
- **Authentication**: jsonwebtoken, bcryptjs
- **Two-Factor Authentication**: otplib, qrcode

## Running with Docker

### Prerequisites
- **Docker** and **Docker Compose** installed

### Quick start
1. Clone the repository
   ```bash
   git clone <REPOSITORY_URL>
   cd twoFa
   ```
2. Create a `.env` file at the project root (example below)
3. Start the services with Docker
   ```bash
   docker compose up -d --build
   ```
4. Run database migrations inside the app container
   ```bash
   docker compose exec app npx prisma migrate deploy
   # Dev alternative (push schema without creating migration files):
   docker compose exec app npx prisma db push
   ```
5. The API will be available at `http://localhost:<PORT>` (see the `PORT` variable in `.env`)

### .env file (example)
```env
# Environment
NODE_ENV=development
PORT=3000

# Database (uses the docker-compose `pgsql` service)
DATABASE_URL=postgresql://docker:docker@pgsql:5432/two_fa?schema=public

# JWT (PEM keys). Generate with OpenSSL, for example:
# openssl genrsa -out jwtRS256.key 2048
# openssl rsa -in jwtRS256.key -pubout -out jwtRS256.key.pub
# Tip: you can encode newlines as \n if keeping on one line
JWT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----
JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----

# 2FA
TWOFA_APP_NAME=TwoFA Demo

# Encryption key (32 bytes for AES-256). Generate with:
# openssl rand -base64 32 | head -c 32
# or: openssl rand -hex 32
ENCRYPTION_KEY=your-32-byte-key-here
```

### Notes
- `docker-compose.yml` brings up two services: `app` (NestJS) and `pgsql` (PostgreSQL).
- `app` ports are defined by `PORT` in `.env` and mapped to the host.
- The database container exposes `5435` on the host for convenience, but the app connects to `pgsql:5432` inside the Docker network.
- The image bundles `prisma/schema.prisma`, so Prisma CLI commands (migrate/db push) run inside the container without extra flags.

## Running Tests

### Prerequisites
- **Node.js** and **pnpm** installed
- **Docker** and **Docker Compose** installed

### Setup
1. Create a `.env.test` file at the project root with the following content:
   ```env
   # Environment
   NODE_ENV=test
   PORT=3001

   # Database (uses the docker-compose test database)
   DATABASE_URL=postgresql://docker:docker@localhost:5435/two_fa_test?schema=public

   # JWT (same keys as development)
   JWT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----
   JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----

   # 2FA
   TWOFA_APP_NAME=TwoFA Demo Test

   # Encryption key (same as development)
   ENCRYPTION_KEY=your-32-byte-key-here
   ```

2. Run the end-to-end tests:
   ```bash
   pnpm test:e2e
   ```

### What the test command does
The `pnpm test:e2e` command will:
1. Start a test PostgreSQL database using Docker Compose
2. Run database migrations
3. Execute all end-to-end tests
4. Clean up the test database

### Test Features
The test suite covers:
- User registration and login
- Two-factor authentication setup and confirmation
- Backup code generation and validation
- 2FA enable/disable functionality
- JWT token validation
- Error handling scenarios