# Authentication System

A full-stack authentication system built with Node.js/Express backend and React frontend. Features JWT-based authentication with refresh tokens, OTP email verification, role-based access control, and session management backed by MySQL.

## Features

- **JWT Authentication** - Access tokens with automatic refresh mechanism via HTTP-only cookies
- **OTP Verification** - Email-based OTP for registration and password reset flows
- **Role-Based Access** - Supports buyer, seller, and admin roles with permission middleware
- **Session Management** - Server-side session tracking with device info, automatic cleanup of expired sessions
- **Rate Limiting** - Tiered rate limits per endpoint (login, registration, OTP requests)
- **Security Hardening** - Helmet headers, bcrypt hashing (configurable rounds), input validation via express-validator
- **Audit Logging** - Database triggers track login events, password changes, and registrations

## Tech Stack

### Backend
- **Runtime**: Node.js 18+
- **Framework**: Express.js with Helmet, CORS, express-rate-limit
- **Database**: MySQL 8 with connection pooling (mysql2)
- **Auth**: JSON Web Tokens (jsonwebtoken), bcrypt
- **Email**: Nodemailer with retry logic
- **Validation**: express-validator

### Frontend
- **Framework**: React 19 with Vite 6
- **State Management**: Context API + useReducer
- **Auth Flow**: AuthProvider with automatic token refresh

## Getting Started

### Prerequisites

- Node.js >= 18.x
- MySQL 8.x
- Gmail account (or SMTP provider) for email delivery

### Backend Setup

```bash
cd backend
npm install
cp .env .env.local   # Edit with your credentials
```

Initialize the database:

```bash
mysql -u root -p < ../database.sql
```

Start the server:

```bash
npm run dev
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user (sends OTP) |
| POST | `/api/auth/verify-otp` | Verify OTP for registration or reset |
| POST | `/api/auth/login` | Login with email/password/role |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Logout current session |
| POST | `/api/auth/logout-all` | Logout from all devices |
| POST | `/api/auth/send-password-reset-otp` | Request password reset OTP |
| POST | `/api/auth/reset-password` | Reset password with OTP |
| GET | `/api/auth/profile` | Get authenticated user profile |

## Project Structure

```
authentication-system/
  backend/
    index.js           # Express server, routes, middleware, DB config
    package.json
    .env               # Environment configuration
  frontend/
    src/
      login.jsx        # Auth context, API service, login UI components
      App.jsx          # Main app shell
      main.jsx         # Entry point
    index.html
    vite.config.js
  database.sql         # Full MySQL schema with triggers and stored procedures
```

## Database Schema

The MySQL schema includes:
- `users` - User accounts with role-specific uniqueness constraints
- `user_sessions` - Token-based sessions with device tracking
- `otp_verifications` - Time-limited OTP records
- `temp_registrations` - Temporary registration data pending OTP verification
- `audit_logs` - Security event audit trail
- `password_history` - Prevents password reuse
- `user_security_settings` - Per-user 2FA and notification preferences
- `rate_limits` - Database-level rate limiting

## License

MIT


## Database Setup

Import the schema:
```bash
mysql -u root -p < database.sql
```
