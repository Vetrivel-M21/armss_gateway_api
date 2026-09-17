<?php
/**
 * ARMSS Gateway Guard
 * Include this file at the very top of every page/route that must only be
 * accessible when launched through the ARMSS Gateway desktop application.
 *
 * Usage:
 *   require_once __DIR__ . '/includes/gateway_guard.php';
 *   gateway_guard_enforce();
 */

const GATEWAY_EIGHT_HOURS_SECONDS = 8 * 60 * 60;
const GATEWAY_REVALIDATE_INTERVAL_SECONDS = 15 * 60; // re-check with gateway every 15 min
const GATEWAY_VALIDATION_URL = 'https://armssgateway.arminfo.in/api/v1/auth/validate-token';
const GATEWAY_HTTP_TIMEOUT  = 3; // seconds

/**
 * Call the gateway's validate-token endpoint.
 *
 * @return array{ok: bool, valid: bool, reason: string}
 */
function gateway_call_validate(string $deviceId, string $token): array
{
    $payload = json_encode(['device_id' => $deviceId, 'token' => $token]);

    $ch = curl_init(GATEWAY_VALIDATION_URL);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_TIMEOUT        => GATEWAY_HTTP_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => GATEWAY_HTTP_TIMEOUT,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);
    curl_close($ch);

    if ($response === false || $httpCode < 200 || $httpCode >= 300) {
        error_log("gateway_guard: call to gateway failed (http=$httpCode, err=$curlErr)");
        return ['ok' => false, 'valid' => false, 'reason' => 'Security verification failed. Device token revoked or invalid.'];
    }

    $data = json_decode($response, true);
    if (!is_array($data)) {
        error_log("gateway_guard: invalid JSON from gateway");
        return ['ok' => false, 'valid' => false, 'reason' => 'Security verification failed. Device token revoked or invalid.'];
    }

    $body  = $data['data'] ?? $data;
    $valid = $body['valid'] ?? $body['is_valid'] ?? false;
    $reason = $body['reason'] ?? '';

    return ['ok' => true, 'valid' => (bool) $valid, 'reason' => (string) $reason];
}

/**
 * Strip gateway credentials from the visible URL after they've been consumed,
 * so the token doesn't linger in the address bar or browser history.
 * Must be called before any output has been sent (uses a JS redirect since
 * PHP can't rewrite the browser's address bar directly after the fact).
 */
function gateway_clean_address_bar(): void
{
    $keysToStrip = ['gateway_device_id', 'device_id', 'gateway_token', 'device_token', 'token', 'entry_secret'];
    $hasAny = false;
    foreach ($keysToStrip as $key) {
        if (isset($_GET[$key])) {
            $hasAny = true;
            break;
        }
    }
    if (!$hasAny) {
        return;
    }

    $query = $_GET;
    foreach ($keysToStrip as $key) {
        unset($query[$key]);
    }
    $cleanQuery = http_build_query($query);
    $cleanUrl = strtok($_SERVER['REQUEST_URI'], '?') . ($cleanQuery ? "?$cleanQuery" : '');

    // Replace the URL client-side without a full reload
    echo "<script>window.history.replaceState({}, document.title, " . json_encode($cleanUrl) . ");</script>";
}

/**
 * Render the "You Are Restricted" access-denied page and terminate the request.
 * A single screen is used for every denial reason — missing credentials, expired
 * session, revoked access, or an unreachable gateway — with the specific reason
 * shown in the notice line at the bottom.
 */
function gateway_deny(string $reason): void
{
    http_response_code(403);
    $safeReason = htmlspecialchars($reason, ENT_QUOTES, 'UTF-8');

    echo <<<HTML
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Access Restricted</title>
<style>
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:#0f172a; font-family:system-ui,sans-serif; padding:1rem; }
  .card { max-width:32rem; width:100%; background:#1e293b; border:1px solid #334155;
          border-radius:1rem; padding:2.5rem; text-align:center; box-shadow:0 25px 50px -12px rgba(0,0,0,.5); }
  .icon { width:5rem; height:5rem; margin:0 auto 1rem; border-radius:9999px; background:rgba(244,63,94,.1);
          border:1px solid rgba(244,63,94,.2); display:flex; align-items:center; justify-content:center; }
  .badge { display:inline-block; padding:.25rem .75rem; border-radius:9999px; font-size:.7rem; font-weight:700;
           background:rgba(244,63,94,.15); color:#fb7185; border:1px solid rgba(244,63,94,.3);
           text-transform:uppercase; letter-spacing:.05em; }
  h1 { color:#fff; font-size:1.75rem; margin:.75rem 0; }
  .box { background:rgba(15,23,42,.7); border:1px solid #334155; border-radius:.75rem; padding:1.25rem;
         text-align:left; margin-top:1.25rem; }
  .box p { margin:.5rem 0; }
  .box .lead { color:#e2e8f0; font-size:.875rem; font-weight:500; }
  .box .sub { color:#94a3b8; font-size:.75rem; }
  .notice { border-top:1px solid #1e293b; margin-top:.75rem; padding-top:.5rem;
            font-family:monospace; font-size:.7rem; color:#fb7185; word-break:break-word; }
</style></head>
<body>
  <div class="card">
    <div class="icon">🔒</div>
    <span class="badge">Access Restricted</span>
    <h1>You Are Restricted</h1>
    <div class="box">
      <p class="lead">Your access to this application has been restricted by the administrator.</p>
      <p class="sub">If you require access, please submit an activation request from the ARMSS Gateway
      desktop application, or contact the ARMSS Infotech Support Team for assistance.</p>
      <div class="notice">Notice: {$safeReason}</div>
    </div>
  </div>
</body></html>
HTML;
    exit;
}

/**
 * Main entry point — call this at the very top of any protected page,
 * before any other output.
 */
function gateway_guard_enforce(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $now = time();

    $urlDeviceId = $_GET['gateway_device_id'] ?? $_GET['device_id'] ?? null;
    $urlToken    = $_GET['gateway_token'] ?? $_GET['token'] ?? $_GET['device_token'] ?? null;

    $sessionDeviceId = $_SESSION['gateway_device_id'] ?? null;
    $sessionToken    = $_SESSION['gateway_token'] ?? null;
    $sessionLoginAt  = $_SESSION['gateway_login_time'] ?? 0;
    $sessionLastCheck = $_SESSION['gateway_last_check'] ?? 0;

    // 1. Enforce 8-hour session expiry
    if ($sessionLoginAt > 0 && ($now - $sessionLoginAt) > GATEWAY_EIGHT_HOURS_SECONDS) {
        session_unset();
        session_destroy();
        gateway_deny('Your 8-hour work session has expired. Please relaunch from ARMSS Gateway.');
    }

    $effectiveDeviceId = $urlDeviceId ?: $sessionDeviceId ?: '';
    $effectiveToken    = $urlToken ?: $sessionToken ?: '';

    // 2. Fast path — already validated this session, and not due for a re-check yet
    $sameCreds = ($sessionDeviceId === $effectiveDeviceId && $sessionToken === $effectiveToken);
    $dueForRecheck = ($now - $sessionLastCheck) >= GATEWAY_REVALIDATE_INTERVAL_SECONDS;

    if ($effectiveDeviceId !== '' && $effectiveToken !== '' && $sameCreds && $sessionLoginAt > 0 && !$dueForRecheck) {
        gateway_clean_address_bar();
        return; // authorized, page proceeds normally
    }

    // 3. Always verify against the live gateway before letting the page proceed
    //    (covers first-time visits, missing credentials, and periodic re-checks alike)
    $result = gateway_call_validate($effectiveDeviceId, $effectiveToken);

    if (!$result['ok']) {
        session_unset();
        session_destroy();
        gateway_deny('Unable to reach ARMSS Gateway verification service.');
    }

    if (!$result['valid']) {
        session_unset();
        session_destroy();
        if ($effectiveDeviceId === '' || $effectiveToken === '') {
            gateway_deny('The requested URL was not found on this server. Direct web browser access without ARMSS Gateway launch authorization is restricted.');
        }
        $reason = $result['reason'] !== '' ? "Access denied: {$result['reason']}" : 'Access denied: Device token revoked or invalid.';
        gateway_deny($reason);
    }

    // 4. Valid — persist/refresh session
    $_SESSION['gateway_device_id']  = $effectiveDeviceId;
    $_SESSION['gateway_token']      = $effectiveToken;
    $_SESSION['gateway_last_check'] = $now;
    if ($sessionLoginAt === 0 || !$sameCreds) {
        $_SESSION['gateway_login_time'] = $now; // only reset the 8h clock on a genuinely new login
    }

    gateway_clean_address_bar();
}