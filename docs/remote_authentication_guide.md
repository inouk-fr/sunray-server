# Remote Authentication Guide

**Sunray Advanced Feature**

## Table of Contents

1. [Overview](#overview)
2. [Use Cases](#use-cases)
3. [How It Works](#how-it-works)
4. [Administrator Guide](#administrator-guide)
5. [User Guide](#user-guide)
6. [Security Considerations](#security-considerations)
7. [Technical Architecture](#technical-architecture)
8. [Troubleshooting](#troubleshooting)

---

## Overview

Remote Authentication is an advanced Sunray feature that allows users to securely authenticate to protected applications from untrusted devices (like shared computers, kiosks, or library terminals) using their personal mobile device's passkey.

### What Problem Does It Solve?

Traditional authentication on shared computers presents security risks:
- **Password Exposure**: Typing passwords on untrusted keyboards
- **Session Hijacking**: Sessions left active on shared devices
- **Credential Theft**: Keyloggers and screen capture malware
- **Privacy Concerns**: Browser history and cached credentials

Remote Authentication eliminates these risks by:
- **Never exposing credentials** to the untrusted device
- **Using mobile biometrics** (fingerprint, Face ID) for verification
- **Creating temporary sessions** with shorter lifetimes
- **Allowing remote termination** of sessions from your mobile device

### Key Benefits

- ✅ **Zero Credential Exposure**: Your passkey never leaves your mobile device
- ✅ **Biometric Security**: Use fingerprint/Face ID for authentication
- ✅ **Session Control**: View and terminate sessions from anywhere
- ✅ **Time-Limited Access**: Sessions expire faster than normal logins
- ✅ **No Software Installation**: Works on any computer with a browser
- ✅ **Audit Trail**: Complete logging of all authentication events

---

## Use Cases

### 1. Shared Office Computers

**Scenario**: You need to check a protected application from a colleague's computer.

**Traditional Risk**: Typing your password on their computer, leaving your credentials in their browser history.

**With Remote Authentication**:
1. Click "Sign in with Mobile" on their computer
2. Scan the QR code with your phone
3. Approve with fingerprint/Face ID
4. Access granted - session expires in 1 hour

### 2. Public Kiosks

**Scenario**: Accessing a company resource from an airport or hotel kiosk.

**Traditional Risk**: Passwords exposed to unknown environment, session left active after use.

**With Remote Authentication**:
- No password typing on public keyboards
- Sessions automatically expire
- Can terminate session remotely if you forget to log out

### 3. Conference Room Displays

**Scenario**: Presenting from a shared conference room computer.

**Traditional Risk**: Logging in exposes credentials, forgetting to log out leaves session active.

**With Remote Authentication**:
- Quick authentication via mobile
- Presenter controls session duration
- Can terminate immediately after presentation from phone

### 4. Temporary Access Needs

**Scenario**: Quick access from a computer you don't own.

**Traditional Risk**: Creating full browser sessions on unfamiliar devices.

**With Remote Authentication**:
- Set custom session duration (15 minutes to 2 hours)
- Session automatically expires
- Zero traces left on the computer

---

## How It Works

### High-Level Flow

```
┌─────────────────┐
│ 1. Computer     │ User visits protected application
│    Request      │ → Redirected to authentication page
└─────────────────┘
         ↓
┌─────────────────┐
│ 2. QR Code      │ User clicks "Sign in with Mobile"
│    Display      │ → QR code displayed with challenge
└─────────────────┘
         ↓
┌─────────────────┐
│ 3. Mobile       │ User scans QR code with mobile app
│    Scan         │ → Challenge received on mobile
└─────────────────┘
         ↓
┌─────────────────┐
│ 4. Biometric    │ User approves with fingerprint/Face ID
│    Verification │ → WebAuthn verification on mobile
└─────────────────┘
         ↓
┌─────────────────┐
│ 5. Session      │ Server creates temporary session
│    Creation     │ → Computer automatically logged in
└─────────────────┘
         ↓
┌─────────────────┐
│ 6. Access       │ User accesses protected application
│    Granted      │ → Session expires after configured duration
└─────────────────┘
```

### Security Flow

1. **Challenge Generation**:
   - Computer requests authentication
   - Worker generates unique, time-limited challenge (QR code)
   - Challenge expires after 5 minutes

2. **Mobile Verification**:
   - User's mobile app scans QR code
   - Mobile retrieves user's WebAuthn credentials from server
   - WebAuthn verification happens **locally on mobile** (fast, secure)
   - Mobile sends verification result to worker

3. **Session Creation**:
   - Worker requests session creation from server
   - Server validates and creates "remote" session
   - Remote sessions have shorter TTL (1 hour default vs 8 hours for normal)
   - Session metadata includes device information

4. **Access Control**:
   - Computer receives session token
   - User can now access protected application
   - Session automatically expires
   - User can terminate session remotely anytime

---

## Administrator Guide

### Prerequisites

- Sunray Advanced Core addon installed (`sunray_advanced_core`)
- At least one protected host configured
- Users registered with passkeys

### Enabling Remote Authentication

#### Step 1: Navigate to Host Configuration

1. Log in to Sunray Admin interface
2. Navigate to **Sunray → Protected Hosts**
3. Select the host where you want to enable Remote Authentication
4. Click **Edit**

#### Step 2: Configure Remote Authentication

1. Go to the **Remote Authentication** tab
2. Enable **Remote Authentication** checkbox
3. Configure session settings:

**Remote Session Duration** (default: 3600 seconds = 1 hour):
- How long remote authentication sessions remain valid
- Recommended: 1-2 hours for most use cases
- Shorter is more secure, longer is more convenient

**Maximum Remote Session Duration** (default: 7200 seconds = 2 hours):
- Maximum duration users can select on their mobile device
- Prevents users from creating excessively long sessions
- Must be ≥ Remote Session Duration

4. Configure session management:

**Enable Session Management** (default: enabled):
- Allows users to view and terminate their active sessions
- Recommended: Keep enabled for user control

**Session Management Access Duration** (default: 120 seconds = 2 minutes):
- How long session management access remains valid after passkey verification
- Prevents unauthorized session termination
- Recommended: 1-3 minutes

5. Click **Save**

### Configuration Best Practices

#### Security-Focused Configuration

For maximum security (e.g., accessing sensitive data from untrusted devices):

```
Remote Session Duration: 900s (15 minutes)
Maximum Remote Session Duration: 1800s (30 minutes)
Session Management Enabled: Yes
Session Management TTL: 60s (1 minute)
```

**Rationale**: Short sessions minimize exposure window, quick session management access prevents stale authorizations.

#### Convenience-Focused Configuration

For better user experience (e.g., known shared computers):

```
Remote Session Duration: 3600s (1 hour)
Maximum Remote Session Duration: 7200s (2 hours)
Session Management Enabled: Yes
Session Management TTL: 180s (3 minutes)
```

**Rationale**: Longer sessions reduce re-authentication frequency while maintaining security boundaries.

#### Balanced Configuration (Recommended)

For most organizations:

```
Remote Session Duration: 2400s (40 minutes)
Maximum Remote Session Duration: 4800s (80 minutes)
Session Management Enabled: Yes
Session Management TTL: 120s (2 minutes)
```

### Monitoring Remote Authentication

#### Audit Logs

All remote authentication events are logged in Sunray's audit system:

1. Navigate to **Sunray → Audit Logs**
2. Filter by event types:
   - `session.remote_created`: Remote session created
   - `session.terminated`: Session terminated by user
   - `auth.challenge_created`: QR code generated
   - `auth.challenge_expired`: QR code expired unused

#### Session Analysis

View active remote sessions:

1. Navigate to **Sunray → Users**
2. Select a user
3. Go to **Active Sessions** tab
4. Filter by **Session Type = Remote**

Key metrics to monitor:
- Average session duration
- Session termination frequency
- Failed authentication attempts
- Unusual access patterns

### Security Policies

#### Recommended Policies

1. **Regular Review**: Review audit logs weekly for unusual patterns
2. **User Training**: Educate users about:
   - Always terminating sessions on shared computers
   - Checking for suspicious sessions in their mobile app
   - Never sharing their mobile device for authentication
3. **Time Restrictions**: Consider disabling Remote Authentication during non-business hours for highly sensitive hosts
4. **Geographic Restrictions**: (Future feature) Limit remote authentication to specific regions

#### Compliance Considerations

For regulated environments (HIPAA, SOC 2, etc.):

- **Audit Retention**: Ensure audit logs are retained per compliance requirements
- **Session Metadata**: Device information is logged for forensic analysis
- **User Consent**: Inform users that session data is logged
- **Access Reviews**: Regular review of who has Remote Authentication access

---

## User Guide

### Prerequisites

- Mobile device with Sunray app installed (or WebAuthn-capable browser)
- Passkey registered with Sunray
- Remote Authentication enabled on the host you want to access

### Authenticating from a Shared Computer

#### Step 1: Visit Protected Application

1. Open a web browser on the shared computer
2. Navigate to the protected application URL
3. You'll be redirected to Sunray's authentication page

#### Step 2: Choose Remote Authentication

1. Click **"Sign in with Mobile"** button
2. A QR code will be displayed on the screen
3. **Note**: The QR code expires after 5 minutes for security

#### Step 3: Scan with Your Mobile Device

1. Open the Sunray mobile app on your phone
2. Tap **"Scan QR Code"** (or use your phone's camera if integrated)
3. Point your camera at the QR code on the computer screen
4. The app will automatically detect and process the code

#### Step 4: Approve with Biometric

1. Your mobile app will show:
   - The application you're accessing
   - The computer's location/IP (if available)
   - Session duration options
2. **Choose session duration** (slider or dropdown):
   - Quick access: 15-30 minutes
   - Extended work: 1-2 hours
   - Custom: Set your own (up to maximum allowed)
3. **Approve with biometric**:
   - Touch ID / Fingerprint sensor
   - Face ID / Facial recognition
   - Device PIN (fallback)

#### Step 5: Access Granted

1. The computer will automatically redirect to the application
2. You're now logged in with a temporary session
3. The session will expire after your chosen duration

### Managing Your Sessions

#### Viewing Active Sessions

**On Mobile App**:
1. Open Sunray mobile app
2. Go to **Settings → Active Sessions**
3. View all devices where you're currently logged in:
   - Session type (Normal / Remote)
   - Device information
   - Location/IP address
   - Time remaining
   - Last activity

**On Web** (requires passkey verification):
1. Visit your Sunray profile page
2. Navigate to **Security → Active Sessions**
3. Authenticate with your passkey
4. View all sessions (valid for 2 minutes)

#### Terminating a Session

**From Mobile App** (Recommended):
1. Open Sunray mobile app
2. Go to **Settings → Active Sessions**
3. Find the session you want to terminate
4. Tap **"End Session"**
5. Confirm termination

**From Web**:
1. Access Active Sessions (see above)
2. Authenticate with passkey
3. Click **"Terminate"** next to the session
4. Confirm action

#### Terminating All Sessions

**Emergency "Sign Out Everywhere"**:
1. Open Sunray mobile app
2. Go to **Settings → Security**
3. Tap **"Sign Out Everywhere Else"**
4. Confirm with biometric
5. All sessions except your current mobile session will be terminated

### Best Practices for Users

#### Do's ✅

- **Always terminate** sessions when done (don't rely on auto-expiration)
- **Choose appropriate duration** - don't request 2 hours if you only need 15 minutes
- **Review sessions weekly** in your mobile app
- **Terminate suspicious sessions** immediately
- **Use biometric authentication** when available (more secure than PIN)
- **Keep your mobile device secure** - it's your authentication key

#### Don'ts ❌

- **Don't share your mobile device** for others to authenticate
- **Don't scan QR codes** from untrusted sources
- **Don't leave sessions active** on public computers
- **Don't authenticate** if the host/application looks suspicious
- **Don't ignore** security alerts from the mobile app

### Troubleshooting

#### QR Code Won't Scan

**Symptoms**: Mobile app can't read the QR code

**Solutions**:
1. Ensure good lighting and camera focus
2. Hold phone steady, about 6-12 inches from screen
3. Try refreshing the QR code (click "Refresh Code")
4. Ensure your mobile app is up to date
5. Check if QR code expired (5 minute limit) - request new one

#### Authentication Fails After Scanning

**Symptoms**: Mobile shows error after biometric approval

**Solutions**:
1. Check internet connection on mobile device
2. Ensure you're registered for this host
3. Verify your passkey is still valid
4. Try requesting a new QR code
5. Contact your administrator if issue persists

#### Computer Doesn't Redirect After Approval

**Symptoms**: Mobile says "Success" but computer still shows QR code

**Solutions**:
1. Wait 5-10 seconds (network delay)
2. Check computer's internet connection
3. Manually refresh the browser page
4. Try scanning QR code again

#### Session Expires Too Quickly

**Symptoms**: Logged out before expected

**Solutions**:
1. Check session duration you selected
2. Ask administrator to increase maximum session duration
3. Use normal authentication (with passkey on the computer) for longer sessions

#### Can't See Active Sessions

**Symptoms**: Session management shows empty or error

**Solutions**:
1. Ensure you're authenticated (passkey verification required)
2. Check if session management is enabled by administrator
3. Verify the 2-minute access window hasn't expired
4. Try re-authenticating with your passkey

---

## Security Considerations

### Threat Model

Remote Authentication is designed to protect against:

1. **Credential Theft**: Passkeys never transmitted to untrusted devices
2. **Keylogging**: No password typing required
3. **Session Hijacking**: Time-limited sessions with device fingerprinting
4. **Unauthorized Access**: Biometric verification required
5. **Forgotten Logout**: Sessions auto-expire, remote termination available

### Security Boundaries

#### What Remote Authentication Protects

✅ **Credentials from exposure** on untrusted devices
✅ **Biometric verification** ensures authorized use
✅ **Time-limited sessions** reduce exposure window
✅ **Audit trail** for compliance and forensics
✅ **Session control** from trusted mobile device

#### What It Doesn't Protect

❌ **Compromised mobile device**: If your phone is hacked, attacker can authenticate
❌ **Screen shoulder-surfing**: Data displayed on computer can be observed
❌ **Application vulnerabilities**: Sunray only controls access, not app security
❌ **Network eavesdropping**: Use HTTPS for end-to-end encryption
❌ **Physical device security**: Lock untrusted computers when stepping away

### Privacy Considerations

**Data Collected**:
- Device information (user agent, IP address, browser)
- Session timestamps (creation, last activity, expiration)
- Authentication events (success, failure, termination)

**Data NOT Collected**:
- Biometric data (stays on your mobile device)
- Application activity (what you do after authentication)
- Mobile device location (unless explicitly enabled)

**Data Retention**:
- Session data: Retained for 90 days after expiration
- Audit logs: Retained per organizational policy
- Device metadata: Deleted with session

---

## Technical Architecture

### System Components

```
┌──────────────────────────────────────────────────┐
│ Computer (Untrusted Device)                     │
│ ┌────────────────────────────────────────────┐  │
│ │ Browser                                    │  │
│ │ - Displays QR code                        │  │
│ │ - Polls for authentication result         │  │
│ │ - Receives session token                  │  │
│ └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
                      ↕ HTTPS
┌──────────────────────────────────────────────────┐
│ Sunray Worker (Edge)                            │
│ ┌────────────────────────────────────────────┐  │
│ │ - Generates QR code challenges            │  │
│ │ - Performs WebAuthn verification          │  │
│ │ - Manages JWT tokens                      │  │
│ │ - Provides session management UI          │  │
│ └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
                      ↕ REST API
┌──────────────────────────────────────────────────┐
│ Sunray Server (Internal)                        │
│ ┌────────────────────────────────────────────┐  │
│ │ - Stores WebAuthn credentials             │  │
│ │ - Manages sessions (creation, validation) │  │
│ │ - Enforces TTL policies                   │  │
│ │ - Generates audit events                  │  │
│ └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
                      ↕ HTTPS
┌──────────────────────────────────────────────────┐
│ Mobile Device (Trusted)                         │
│ ┌────────────────────────────────────────────┐  │
│ │ Sunray Mobile App                         │  │
│ │ - Scans QR codes                          │  │
│ │ - Performs biometric verification         │  │
│ │ - Manages active sessions                 │  │
│ └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

### Authentication Flow

1. **Challenge Generation** (Computer → Worker):
   ```
   GET /sunray-wrkr/v1/remote-auth/challenge
   Response: { challenge_id, qr_data, expires_at }
   ```

2. **Challenge Polling** (Computer → Worker):
   ```
   GET /sunray-wrkr/v1/remote-auth/poll/{challenge_id}
   Response: { status: "pending" | "approved" | "expired" }
   ```

3. **Credential Fetch** (Mobile App → Server via Worker):
   ```
   GET /sunray-srvr/v1/users/{username}
   Response: { user_id, passkeys: [...] }
   ```

4. **WebAuthn Verification** (Mobile App → Worker):
   ```
   Mobile performs local WebAuthn verification
   ```

5. **Session Creation** (Worker → Server):
   ```
   POST /sunray-srvr/v1/sessions/remote
   Request: { user_id, protected_host_id, session_duration, device_info }
   Response: { session_id, expires_at, session_type: "remote" }
   ```

6. **Token Generation** (Worker):
   ```
   Worker generates JWT token with session_id
   ```

7. **Computer Receives Session** (Worker → Computer):
   ```
   Poll response changes to: { status: "approved", token: "jwt_token" }
   Computer stores token in cookie
   ```

### Session Management Flow

**List Sessions** (Mobile App → Server via Worker):
```
GET /sunray-srvr/v1/sessions/list/{user_id}?protected_host_id=123
Response: { sessions: [ { session_id, type, host, created_at, expires_at, device_info }, ... ] }
```

**Terminate Session** (Mobile App → Server via Worker):
```
DELETE /sunray-srvr/v1/sessions/{session_id}
Response: { success: true, message: "Session terminated" }
```

### Configuration

**Server-Side** (per Protected Host):
```json
{
  "remote_auth": {
    "enabled": true,
    "session_ttl": 3600,          // Default duration (1 hour)
    "max_session_ttl": 7200,      // Maximum duration (2 hours)
    "session_mgmt_enabled": true,
    "session_mgmt_ttl": 120,      // Session mgmt access (2 minutes)
    "polling_interval": 2,        // Computer poll frequency (2 seconds)
    "challenge_ttl": 300          // QR code lifetime (5 minutes)
  }
}
```

**Worker Behavior**:
- Detects feature by presence of `remote_auth` object in config response
- If absent, hides "Sign in with Mobile" button
- Polls server every 2 seconds for challenge verification
- Enforces session TTL limits from server configuration

---

## Troubleshooting

### Common Issues

#### Issue: "Remote Authentication Not Available"

**Cause**: Feature not enabled or addon not installed

**Resolution**:
1. Verify `sunray_advanced_core` addon is installed
2. Check Protected Host configuration has Remote Authentication enabled
3. Refresh worker configuration (may take up to 5 minutes for cache)

#### Issue: QR Code Expires Immediately

**Cause**: System time synchronization problem

**Resolution**:
1. Verify server, worker, and mobile device clocks are synchronized
2. Check for NTP configuration on server
3. Verify timezone settings match

#### Issue: Sessions Terminate Unexpectedly

**Cause**: TTL misconfiguration or session cleanup

**Resolution**:
1. Check configured session TTL vs user expectations
2. Verify no concurrent logins causing session invalidation
3. Review audit logs for session termination events
4. Check if admin forcefully cleared sessions

#### Issue: Mobile App Can't Authenticate

**Cause**: Credential mismatch or network issues

**Resolution**:
1. Verify user has registered passkey for this host
2. Check mobile device network connectivity
3. Ensure mobile app has latest credentials (refresh user data)
4. Try re-registering passkey

#### Issue: High Authentication Latency

**Cause**: Network delay or worker performance

**Resolution**:
1. Check network latency between mobile device and worker
2. Verify worker health and response times
3. Consider regional worker deployment for geo-distributed users
4. Review server database performance

### Debug Mode

**Enable Debug Logging** (Administrator):

1. Navigate to **Sunray → System Settings**
2. Enable **Debug Mode** for Remote Authentication
3. Reproduce the issue
4. Check logs at `/var/log/sunray/remote_auth.log`

**Mobile App Debug Mode**:

1. Open Sunray mobile app
2. Go to **Settings → Advanced → Debug**
3. Enable **Remote Authentication Debug Logs**
4. Reproduce issue
5. Export logs via **Settings → Support → Export Logs**

### Getting Help

If you continue to experience issues:

1. **Collect Information**:
   - Exact error message
   - Steps to reproduce
   - Server and worker versions
   - Mobile app version
   - Relevant log entries

2. **Check Documentation**:
   - [API Contract](./API_CONTRACT.md) for technical details
   - [CLAUDE.md](../CLAUDE.md) for development information

3. **Contact Support**:
   - Email: support@sunray.example.com
   - Include collected information from step 1
   - Attach debug logs if available

---

## Conclusion

Remote Authentication provides a secure and convenient way to access protected applications from untrusted devices. By leveraging mobile passkeys and temporary sessions, it eliminates credential exposure while maintaining strong security.

**Remember**:
- Always terminate sessions when done
- Review active sessions regularly
- Choose appropriate session durations
- Report suspicious activity immediately

For additional information:
- **Technical Details**: See [API Contract](./API_CONTRACT.md)
- **Development Guide**: See [CLAUDE.md](../CLAUDE.md)
- **Security Deployment**: See [Deployment Security Guide](./sunray_deployment_security.md)
