import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { validateRedirectUrl } from '../services/authService.js';
import { normalizeEmail } from '../services/userService.js';
import { getAllFiles, updateFileRecord, getFileByToken } from '../services/metadataService.js';
import { SCAN_STATUS } from '../services/malwareScanner.js';
import { parseCookies } from '../middleware/authMiddleware.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

/**
 * Registers comprehensive tests for User Authentication and Recipient-Based File Authorization.
 * @param {Function} getBaseUrl - Returns the base URL of the active test server
 */
export function registerAuthTests(getBaseUrl) {
  test('Suite: SecuShare Authentication & Recipient Authorization', async (t) => {
    // Ensure clean state for test run
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(USERS_FILE, JSON.stringify([], null, 2), 'utf-8');
    await fs.writeFile(SESSIONS_FILE, JSON.stringify([], null, 2), 'utf-8');

    let aliceCookie = null;
    let bobCookie = null;
    let restrictedToken = null;
    let restrictedWithPwdToken = null;
    let pendingRecipientToken = null;
    let publicToken = null;

    const sampleContent = 'Protected confidential document content 1234567890';
    const sharedPassword = 'TopSecretPassword123!';

    // Helper to upload a file
    async function uploadTestFile({ recipients = null, password = null, downloadPolicy = 'unlimited', downloadLimit = null, filename = 'doc.txt' }) {
      const formData = new FormData();
      const blob = new Blob([sampleContent], { type: 'text/plain' });
      formData.append('file', blob, filename);
      formData.append('expiry', '24h');
      if (recipients) formData.append('recipients', recipients);
      if (password) formData.append('password', password);
      if (downloadPolicy) formData.append('downloadPolicy', downloadPolicy);
      if (downloadLimit) formData.append('downloadLimit', String(downloadLimit));

      const res = await fetch(`${getBaseUrl()}/api/files`, {
        method: 'POST',
        body: formData
      });
      assert.equal(res.status, 201);
      const data = await res.json();
      return data.file;
    }

    /* =========================================================================
     * SECTION 1: Registration and Accounts
     * ========================================================================= */
    await t.test('Section 1: Registration and Accounts', async (sub) => {
      // 1. Successful registration
      await sub.test('1. Successful registration creates account and returns 201', async () => {
        const res = await fetch(`${getBaseUrl()}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'alice@example.com', password: 'Password1234!' })
        });
        assert.equal(res.status, 201);
        const data = await res.json();
        assert.equal(data.success, true);
        assert.equal(data.user.email, 'alice@example.com');
        assert.ok(data.user.id);
        assert.equal(data.user.passwordHash, undefined, 'Must not return password hash');
        assert.equal(data.user.passwordSalt, undefined, 'Must not return password salt');

        const cookieHeader = res.headers.get('set-cookie');
        assert.ok(cookieHeader, 'Registration should establish a session cookie');
        aliceCookie = cookieHeader.split(';')[0];
      });

      // 2. Duplicate email rejection
      await sub.test('2. Duplicate exact email registration is rejected with 409', async () => {
        const res = await fetch(`${getBaseUrl()}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'alice@example.com', password: 'DifferentPassword123!' })
        });
        assert.equal(res.status, 409);
        const data = await res.json();
        assert.ok(data.error.includes('already exists'));
      });

      // 3. Duplicate rejection when capitalization differs
      await sub.test('3. Duplicate rejection when capitalization differs', async () => {
        const res = await fetch(`${getBaseUrl()}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'ALICE@EXAMPLE.COM', password: 'DifferentPassword123!' })
        });
        assert.equal(res.status, 409);
      });

      // 4. Duplicate rejection when surrounding whitespace differs
      await sub.test('4. Duplicate rejection when surrounding whitespace differs', async () => {
        const res = await fetch(`${getBaseUrl()}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: '   alice@example.com   ', password: 'DifferentPassword123!' })
        });
        assert.equal(res.status, 409);
      });

      // 5. Password is not stored in plaintext
      await sub.test('5. Passwords are never stored in plaintext', async () => {
        const usersRaw = await fs.readFile(USERS_FILE, 'utf-8');
        assert.equal(usersRaw.includes('Password1234!'), false, 'Plaintext password must not appear in users.json');
        const users = JSON.parse(usersRaw);
        const alice = users.find((u) => u.email === 'alice@example.com');
        assert.ok(alice);
        assert.equal(typeof alice.passwordHash, 'string');
        assert.equal(alice.passwordHash.length, 128, 'scrypt 64-byte key encoded in hex should be 128 characters');
        assert.equal(typeof alice.passwordSalt, 'string');
        assert.equal(alice.passwordSalt.length, 32, '16-byte random salt encoded in hex should be 32 characters');
      });

      // Register bob for recipient testing
      await sub.test('Register second user bob@example.com', async () => {
        const res = await fetch(`${getBaseUrl()}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'bob@example.com', password: 'BobPassword1234!' })
        });
        assert.equal(res.status, 201);
        const cookieHeader = res.headers.get('set-cookie');
        bobCookie = cookieHeader.split(';')[0];
      });

      // 6. Correct password login succeeds
      await sub.test('6. Correct password login succeeds and returns session cookie', async () => {
        const res = await fetch(`${getBaseUrl()}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'alice@example.com', password: 'Password1234!' })
        });
        assert.equal(res.status, 200);
        const data = await res.json();
        assert.equal(data.success, true);
        assert.equal(data.user.email, 'alice@example.com');
        const cookieHeader = res.headers.get('set-cookie');
        assert.ok(cookieHeader);
        aliceCookie = cookieHeader.split(';')[0];
      });

      // 7. Incorrect password login fails
      await sub.test('7. Incorrect password login fails with generic 401', async () => {
        const res = await fetch(`${getBaseUrl()}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'alice@example.com', password: 'WrongPassword!' })
        });
        assert.equal(res.status, 401);
        const data = await res.json();
        assert.equal(data.error, 'Invalid email or password.');
      });

      // 8. Invalid input is rejected safely
      await sub.test('8. Invalid input rejected safely (short password, bad email syntax)', async () => {
        // Password too short (< 8)
        const shortRes = await fetch(`${getBaseUrl()}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'valid@example.com', password: 'short' })
        });
        assert.equal(shortRes.status, 400);

        // Invalid email syntax
        const badEmailRes = await fetch(`${getBaseUrl()}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'not-an-email', password: 'Password1234!' })
        });
        assert.equal(badEmailRes.status, 400);
      });

      // 9. Repeated failed logins are rate-limited
      await sub.test('9. Repeated failed logins are rate-limited with 429', async () => {
        const bruteEmail = 'victim_brute@example.com';
        // 5 consecutive failed attempts
        for (let i = 0; i < 5; i++) {
          await fetch(`${getBaseUrl()}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: bruteEmail, password: 'WrongPassword!' })
          });
        }

        // 6th attempt should be blocked by rate limiter
        const blockedRes = await fetch(`${getBaseUrl()}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: bruteEmail, password: 'WrongPassword!' })
        });
        assert.equal(blockedRes.status, 429);
        const data = await blockedRes.json();
        assert.ok(data.error.includes('Too many failed login attempts'));
      });
    });

    /* =========================================================================
     * SECTION 2: Sessions
     * ========================================================================= */
    await t.test('Section 2: Persistent Server Sessions', async (sub) => {
      // 10. Successful login creates a server-managed session
      await sub.test('10. Successful login creates a server-managed session stored in sessions.json', async () => {
        const sessionsRaw = await fs.readFile(SESSIONS_FILE, 'utf-8');
        const sessions = JSON.parse(sessionsRaw);
        assert.ok(sessions.length > 0);
        const cookieId = aliceCookie.replace('secushare_session=', '');
        const found = sessions.find((s) => s.id === cookieId);
        assert.ok(found, 'Session ID from cookie must exist in sessions.json');
        assert.ok(found.userId);
        assert.ok(found.expiresAt);
      });

      // 11. Authenticated session remains valid within configured lifetime
      await sub.test('11. Authenticated session remains valid on /api/auth/me', async () => {
        const res = await fetch(`${getBaseUrl()}/api/auth/me`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(res.status, 200);
        const data = await res.json();
        assert.equal(data.authenticated, true);
        assert.equal(data.user.email, 'alice@example.com');
      });

      // 12. Expired sessions are rejected
      await sub.test('12. Expired sessions are rejected and invalidated', async () => {
        // Create a temporary expired session directly in sessions.json
        const sessions = JSON.parse(await fs.readFile(SESSIONS_FILE, 'utf-8'));
        const expiredId = crypto.randomBytes(32).toString('base64url');
        sessions.push({
          id: expiredId,
          userId: 'some-user-id',
          createdAt: new Date(Date.now() - 1000000).toISOString(),
          expiresAt: new Date(Date.now() - 5000).toISOString() // Expired 5 seconds ago
        });
        await fs.writeFile(SESSIONS_FILE, JSON.stringify(sessions, null, 2), 'utf-8');

        const res = await fetch(`${getBaseUrl()}/api/auth/me`, {
          headers: { Cookie: `secushare_session=${expiredId}` }
        });
        assert.equal(res.status, 200);
        const data = await res.json();
        assert.equal(data.authenticated, false, 'Expired session must not be authenticated');
      });

      // 13. Logout invalidates the session
      await sub.test('13. Logout invalidates the session on the server', async () => {
        // Log in to get a dedicated session to log out
        const loginRes = await fetch(`${getBaseUrl()}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'alice@example.com', password: 'Password1234!' })
        });
        const testCookie = loginRes.headers.get('set-cookie').split(';')[0];
        const sessionId = testCookie.replace('secushare_session=', '');

        const logoutRes = await fetch(`${getBaseUrl()}/api/auth/logout`, {
          method: 'POST',
          headers: { Cookie: testCookie }
        });
        assert.equal(logoutRes.status, 200);

        // Verify session is purged from sessions.json
        const sessions = JSON.parse(await fs.readFile(SESSIONS_FILE, 'utf-8'));
        assert.equal(sessions.some((s) => s.id === sessionId), false, 'Logged out session must be destroyed');
      });

      // 14. An invalidated session cannot access restricted content
      await sub.test('14. An invalidated session cannot access /api/auth/me', async () => {
        const fakeCookie = `secushare_session=${crypto.randomBytes(32).toString('base64url')}`;
        const res = await fetch(`${getBaseUrl()}/api/auth/me`, {
          headers: { Cookie: fakeCookie }
        });
        const data = await res.json();
        assert.equal(data.authenticated, false);
      });

      // 15. The session cookie has appropriate security attributes
      await sub.test('15. Session cookie sets HttpOnly and SameSite attributes', async () => {
        const res = await fetch(`${getBaseUrl()}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'alice@example.com', password: 'Password1234!' })
        });
        const cookieHeader = res.headers.get('set-cookie');
        assert.ok(cookieHeader.toLowerCase().includes('httponly'), 'Must include HttpOnly');
        assert.ok(cookieHeader.toLowerCase().includes('samesite=lax'), 'Must include SameSite');
        assert.ok(cookieHeader.toLowerCase().includes('path=/'), 'Must include Path=/');
        aliceCookie = cookieHeader.split(';')[0];
      });
    });

    /* =========================================================================
     * SECTION 3: Public Links
     * ========================================================================= */
    await t.test('Section 3: Public Links Remain Public', async (sub) => {
      // 16. Anonymous upload still works
      await sub.test('16. Anonymous upload without login works', async () => {
        const file = await uploadTestFile({ filename: 'public_anon.txt' });
        assert.ok(file.shareToken);
        assert.equal(file.isRestricted, false);
        publicToken = file.shareToken;
      });

      // 17. A public link remains accessible without login
      await sub.test('17. Public link can be downloaded without login', async () => {
        const metaRes = await fetch(`${getBaseUrl()}/api/files/${publicToken}`);
        assert.equal(metaRes.status, 200);
        const meta = await metaRes.json();
        assert.equal(meta.isRestricted, false);

        const dlRes = await fetch(`${getBaseUrl()}/api/files/${publicToken}/download`);
        assert.equal(dlRes.status, 200);
        const text = await dlRes.text();
        assert.equal(text, sampleContent);
      });

      // 18. A public link with a configured file password still requires that password
      await sub.test('18. Public link with file password requires password from anonymous visitor', async () => {
        const file = await uploadTestFile({ password: 'FilePassword123!', filename: 'public_pwd.txt' });
        
        // Without password -> 401
        const rejectRes = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`);
        assert.equal(rejectRes.status, 401);

        // With correct password -> 200
        const okRes = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'FilePassword123!' })
        });
        assert.equal(okRes.status, 200);
        assert.equal(await okRes.text(), sampleContent);
      });

      // 19. Public links remain subject to expiry and download limits
      await sub.test('19. Public one-time link enforces download limit', async () => {
        const file = await uploadTestFile({ downloadPolicy: 'one_time', filename: 'public_onetime.txt' });
        
        // 1st download succeeds
        const firstRes = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`);
        assert.equal(firstRes.status, 200);

        // 2nd download is rejected with 410
        const secondRes = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`);
        assert.equal(secondRes.status, 410);
      });
    });

    /* =========================================================================
     * SECTION 4: Restricted Links & Recipient Authorization
     * ========================================================================= */
    await t.test('Section 4: Restricted Links and Recipient Authorization', async (sub) => {
      // Setup restricted file for Alice only
      const restrictedFile = await uploadTestFile({
        recipients: 'alice@example.com',
        filename: 'confidential_alice.txt'
      });
      restrictedToken = restrictedFile.shareToken;
      assert.equal(restrictedFile.isRestricted, true);

      // 20. Logged-out visitor cannot download restricted file directly
      await sub.test('20. Logged-out visitor cannot download restricted file (401)', async () => {
        const res = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}/download`);
        assert.equal(res.status, 401);
        const data = await res.json();
        assert.equal(data.authRequired, true);
      });

      // 21. Logged-out visitor is directed to login/register on metadata endpoint
      await sub.test('21. Logged-out visitor receives 401 with redirectUrl on metadata query', async () => {
        const res = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}`);
        assert.equal(res.status, 401);
        const data = await res.json();
        assert.equal(data.authRequired, true);
        assert.ok(data.redirectUrl.includes('/login?redirect='));
      });

      // 22. Successful authentication returns visitor to original share link
      await sub.test('22. Redirect flow preserves valid relative destination', () => {
        const target = validateRedirectUrl(`/share/${restrictedToken}`);
        assert.equal(target, `/share/${restrictedToken}`);
      });

      // 23. Redirect validation rejects external or unsafe destinations
      await sub.test('23. Redirect validation prevents open redirects', () => {
        assert.equal(validateRedirectUrl('https://evil.com'), '/');
        assert.equal(validateRedirectUrl('//evil.com'), '/');
        assert.equal(validateRedirectUrl('/\\evil.com'), '/');
        assert.equal(validateRedirectUrl('javascript:alert(1)'), '/');
        assert.equal(validateRedirectUrl('data:text/html,evil'), '/');
        assert.equal(validateRedirectUrl(''), '/');
        assert.equal(validateRedirectUrl(null), '/');
      });

      // 24. Authorized user can access restricted link
      await sub.test('24. Authorized user (Alice) can access metadata and download file', async () => {
        const metaRes = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(metaRes.status, 200);
        const meta = await metaRes.json();
        assert.equal(meta.isRestricted, true);
        assert.equal(meta.authorizedRecipients, undefined, 'Must not expose recipient list');

        const dlRes = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(dlRes.status, 200);
        const content = await dlRes.text();
        assert.equal(content, sampleContent);
      });

      // 25. Unauthorized logged-in user is denied
      await sub.test('25. Unauthorized logged-in user (Bob) receives 403 Forbidden', async () => {
        const metaRes = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}`, {
          headers: { Cookie: bobCookie }
        });
        assert.equal(metaRes.status, 403);
        const meta = await metaRes.json();
        assert.equal(meta.accessDenied, true);

        const dlRes = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}/download`, {
          headers: { Cookie: bobCookie }
        });
        assert.equal(dlRes.status, 403);
        const dl = await dlRes.json();
        assert.equal(dl.accessDenied, true);
      });

      // 26. Email matching ignores capitalization and surrounding whitespace
      await sub.test('26. Recipient authorization ignores case and whitespace differences', async () => {
        // Upload restricted file specifying mixed-case and whitespace
        const file = await uploadTestFile({
          recipients: '   ALICE@EXAMPLE.COM   ',
          filename: 'case_test.txt'
        });

        // Alice (registered as alice@example.com) should match
        const dlRes = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(dlRes.status, 200);
      });

      // 27. Pending recipient permission works after matching user registers
      await sub.test('27. Pending recipient permission works when user registers later', async () => {
        const futureEmail = 'charlie@future-recipient.com';
        // Upload restricted to Charlie before Charlie registers
        const file = await uploadTestFile({
          recipients: futureEmail,
          filename: 'for_charlie.txt'
        });

        // Unauthenticated access fails
        const initialRes = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`);
        assert.equal(initialRes.status, 401);

        // Charlie registers later
        const regRes = await fetch(`${getBaseUrl()}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: futureEmail, password: 'CharliePassword123!' })
        });
        assert.equal(regRes.status, 201);
        const charlieCookie = regRes.headers.get('set-cookie').split(';')[0];

        // Charlie logs in and downloads successfully
        const dlRes = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: charlieCookie }
        });
        assert.equal(dlRes.status, 200);
        assert.equal(await dlRes.text(), sampleContent);
      });

      // 28, 29, 30. File password and recipient authorization work together
      await sub.test('28-30. File password + Recipient authorization both required', async () => {
        // File restricted to Alice AND requires file password
        const file = await uploadTestFile({
          recipients: 'alice@example.com',
          password: sharedPassword,
          filename: 'double_protected.txt'
        });
        restrictedWithPwdToken = file.shareToken;

        // 28: Authorized recipient without file password -> 401 Password Required
        const noPwdRes = await fetch(`${getBaseUrl()}/api/files/${restrictedWithPwdToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(noPwdRes.status, 401);
        const noPwdData = await noPwdRes.json();
        assert.equal(noPwdData.authRequired, false);
        assert.ok(noPwdData.error.includes('Password required'));

        // 29: Unauthorized user (Bob) WITH correct file password -> 403 Forbidden (cannot bypass recipient authorization)
        const bobWithPwdRes = await fetch(`${getBaseUrl()}/api/files/${restrictedWithPwdToken}/download`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: bobCookie
          },
          body: JSON.stringify({ password: sharedPassword })
        });
        assert.equal(bobWithPwdRes.status, 403);
        const bobData = await bobWithPwdRes.json();
        assert.equal(bobData.accessDenied, true);

        // 30: Authorized user (Alice) with WRONG file password -> 401 Incorrect password
        const wrongPwdRes = await fetch(`${getBaseUrl()}/api/files/${restrictedWithPwdToken}/download`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: aliceCookie
          },
          body: JSON.stringify({ password: 'WrongPassword!' })
        });
        assert.equal(wrongPwdRes.status, 401);
        const wrongPwdData = await wrongPwdRes.json();
        assert.ok(wrongPwdData.error.includes('Incorrect password'));

        // Authorized user (Alice) with CORRECT file password -> 200 OK
        const correctRes = await fetch(`${getBaseUrl()}/api/files/${restrictedWithPwdToken}/download`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: aliceCookie
          },
          body: JSON.stringify({ password: sharedPassword })
        });
        assert.equal(correctRes.status, 200);
        assert.equal(await correctRes.text(), sampleContent);
      });

      // 31. Protected file bytes are not returned when authorization fails
      await sub.test('31. Protected file bytes are never returned on failed authorization', async () => {
        const failRes = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}/download`, {
          headers: { Cookie: bobCookie }
        });
        assert.equal(failRes.status, 403);
        const rawBody = await failRes.text();
        assert.equal(rawBody.includes(sampleContent), false, 'File bytes must never leak on 403');
      });
    });

    /* =========================================================================
     * SECTION 5: Existing Security and Lifecycle Behavior
     * ========================================================================= */
    await t.test('Section 5: Existing Security and Lifecycle Preservation', async (sub) => {
      // 32. Expiry enforcement still works
      await sub.test('32. Expiry enforcement rejects expired restricted files with 410', async () => {
        const file = await uploadTestFile({ recipients: 'alice@example.com' });
        const record = await getFileByToken(file.shareToken);
        // Artificially expire the record
        await updateFileRecord(record.id, {
          expiresAt: new Date(Date.now() - 10000).toISOString()
        });

        const res = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(res.status, 410);
      });

      // 33. Download limits still work on restricted files
      await sub.test('33. Download limits still enforced on restricted files', async () => {
        const file = await uploadTestFile({
          recipients: 'alice@example.com',
          downloadPolicy: 'limited',
          downloadLimit: 2
        });

        // 1st download -> OK
        const res1 = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(res1.status, 200);

        // 2nd download -> OK
        const res2 = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(res2.status, 200);

        // 3rd download -> 410 Limit Reached
        const res3 = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(res3.status, 410);
      });

      // 34. One-time download behavior works on restricted files
      await sub.test('34. One-time download allows single access on restricted file', async () => {
        const file = await uploadTestFile({
          recipients: 'alice@example.com',
          downloadPolicy: 'one_time'
        });

        const res1 = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(res1.status, 200);

        const res2 = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(res2.status, 410);
      });

      // 35. Concurrent requests cannot bypass download limits
      await sub.test('35. Concurrent requests cannot bypass one-time download limit', async () => {
        const file = await uploadTestFile({
          recipients: 'alice@example.com',
          downloadPolicy: 'one_time'
        });

        const promises = Array.from({ length: 6 }, () =>
          fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
            headers: { Cookie: aliceCookie }
          })
        );

        const results = await Promise.all(promises);
        const statusCodes = results.map((r) => r.status);
        const successCount = statusCodes.filter((s) => s === 200).length;
        const exhaustedCount = statusCodes.filter((s) => s === 410).length;

        assert.equal(successCount, 1, 'Exactly one concurrent download must succeed');
        assert.equal(exhaustedCount, 5, 'All other concurrent downloads must receive 410');
      });

      // 36. Existing encryption and integrity verification preserved
      await sub.test('36. AES-256-GCM encryption at rest and SHA-256 integrity preserved', async () => {
        const file = await uploadTestFile({ recipients: 'alice@example.com' });
        const record = await getFileByToken(file.shareToken);
        assert.equal(record.storageFormat, 'encrypted-v2');
        assert.equal(record.encryption.algorithm, 'aes-256-gcm');
        assert.ok(record.integrity.expectedDigest);
      });

      // 37. Integrity failure prevents delivery
      await sub.test('37. Tampered SHA-256 digest prevents file delivery', async () => {
        const file = await uploadTestFile({ recipients: 'alice@example.com' });
        const record = await getFileByToken(file.shareToken);
        // Tamper with expected digest
        await updateFileRecord(record.id, {
          integrity: {
            algorithm: 'sha256',
            expectedDigest: '0000000000000000000000000000000000000000000000000000000000000000',
            version: 1
          }
        });

        const res = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(res.status, 500);
      });

      // 38. The existing not_scanned state is not presented as malware-free
      await sub.test('38. not_scanned scan status preserved and not reported clean', async () => {
        const file = await uploadTestFile({ filename: 'scan_check.txt' });
        assert.equal(file.scanStatus, SCAN_STATUS.NOT_SCANNED);
      });

      // 39. Existing scanner gate is not bypassed (INFECTED status blocks download)
      await sub.test('39. INFECTED file is blocked by accessService with 403', async () => {
        const file = await uploadTestFile({ recipients: 'alice@example.com' });
        const record = await getFileByToken(file.shareToken);
        await updateFileRecord(record.id, {
          scanStatus: SCAN_STATUS.INFECTED
        });

        const res = await fetch(`${getBaseUrl()}/api/files/${file.shareToken}/download`, {
          headers: { Cookie: aliceCookie }
        });
        assert.equal(res.status, 403);
      });

      // 40. There are no new routes that allow editing or disabling a generated share link
      await sub.test('40. Share links are immutable: PATCH, PUT, DELETE routes do not exist (404)', async () => {
        const patchRes = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ authorizedRecipients: [] })
        });
        assert.equal(patchRes.status, 404);

        const putRes = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ downloadLimit: 999 })
        });
        assert.equal(putRes.status, 404);

        const deleteRes = await fetch(`${getBaseUrl()}/api/files/${restrictedToken}`, {
          method: 'DELETE'
        });
        assert.equal(deleteRes.status, 404);
      });
    });
  });
}
