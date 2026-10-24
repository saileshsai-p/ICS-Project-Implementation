import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

import {
  createDisposableInstall,
  destroyDisposableInstall,
  runInChild
} from './helpers/childRunner.js';

/**
 * Master Encryption Key Lifecycle Tests
 *
 * Key resolution happens once per process and depends on the filesystem state
 * at startup, so each scenario runs in its own child process against its own
 * disposable installation directory. Only throwaway keys are ever generated.
 */
export function registerKeyManagementTests() {
  test('Suite: Master Key Lifecycle', async (t) => {

    await t.test('K1. Fresh installation initializes a key and persists it before use', () => {
      const install = createDisposableInstall({ metadataRecords: [], storedFiles: [] });

      try {
        const run = runInChild({
          env: {
            SECUSHARE_DATA_DIR: install.dataDir,
            SECUSHARE_STORAGE_DIR: install.storageDir,
            SECUSHARE_ENV_FILE: install.envFile,
            __install: install.root
          },
          code: `
            const { getMasterKey, inspectEncryptedState } = await import(SERVICES + '/encryptionService.js');
            const state = inspectEncryptedState();
            const key = getMasterKey();
            console.log('RESULT:' + JSON.stringify({
              freshDetected: state.existing === false,
              keyBytes: key.length,
              // Resolving twice in one process must return the identical key.
              stableAcrossCalls: key.equals(getMasterKey())
            }));
          `
        });

        assert.equal(run.status, 0, `child failed: ${run.stderr}`);
        assert.ok(run.result, 'child must report a result');
        assert.equal(run.result.freshDetected, true, 'empty install must be detected as fresh');
        assert.equal(run.result.keyBytes, 32, 'master key must be 32 bytes');
        assert.equal(run.result.stableAcrossCalls, true);

        // The key must have been written to the configured env file.
        assert.ok(fs.existsSync(install.envFile), 'env file must be created on first run');
        const contents = fs.readFileSync(install.envFile, 'utf-8');
        assert.match(
          contents,
          /^FILE_ENCRYPTION_MASTER_KEY=[0-9a-f]{64}$/m,
          'persisted entry must be a 64-character hex key'
        );
      } finally {
        destroyDisposableInstall(install.root);
      }
    });

    await t.test('K2. A file encrypted on first run is decryptable by a later process', () => {
      const install = createDisposableInstall({ metadataRecords: [], storedFiles: [] });

      try {
        // Process 1: initialize the key and encrypt a file.
        const encryptRun = runInChild({
          env: {
            SECUSHARE_DATA_DIR: install.dataDir,
            SECUSHARE_STORAGE_DIR: install.storageDir,
            SECUSHARE_ENV_FILE: install.envFile,
            __install: install.root
          },
          code: `
            import fs from 'node:fs';
            import path from 'node:path';
            const { encryptFileToStorage } = await import(SERVICES + '/encryptionService.js');
            const { TEMP_DIR } = await import(SERVICES + '/fileService.js');
            const plaintextPath = path.join(TEMP_DIR, 'k2-source.txt');
            fs.writeFileSync(plaintextPath, 'persistence-round-trip-payload', 'utf-8');
            const { encryptionMeta } = await encryptFileToStorage(plaintextPath, 'k2-stored.dat');
            console.log('RESULT:' + JSON.stringify({ encryptionMeta }));
          `
        });

        assert.equal(encryptRun.status, 0, `encrypt child failed: ${encryptRun.stderr}`);
        assert.ok(encryptRun.result?.encryptionMeta, 'encryption metadata must be returned');

        // Process 2: fresh process, key comes only from the persisted env file.
        const decryptRun = runInChild({
          env: {
            SECUSHARE_DATA_DIR: install.dataDir,
            SECUSHARE_STORAGE_DIR: install.storageDir,
            SECUSHARE_ENV_FILE: install.envFile,
            __install: install.root
          },
          code: `
            import fs from 'node:fs';
            const meta = ${JSON.stringify(encryptRun.result.encryptionMeta)};
            const { decryptStorageToTemp } = await import(SERVICES + '/encryptionService.js');
            const outPath = await decryptStorageToTemp('k2-stored.dat', meta);
            const recovered = fs.readFileSync(outPath, 'utf-8');
            fs.unlinkSync(outPath);
            console.log('RESULT:' + JSON.stringify({ recovered }));
          `
        });

        assert.equal(decryptRun.status, 0, `decrypt child failed: ${decryptRun.stderr}`);
        assert.equal(
          decryptRun.result.recovered,
          'persistence-round-trip-payload',
          'persisted key must still decrypt the file after restart'
        );
      } finally {
        destroyDisposableInstall(install.root);
      }
    });

    await t.test('K3. Key persistence failure aborts instead of using an ephemeral key', () => {
      const install = createDisposableInstall({ metadataRecords: [], storedFiles: [] });

      try {
        // Point the env file at a path inside a directory that does not exist,
        // so appending to it cannot succeed.
        const unwritableEnvFile = path.join(install.root, 'no-such-dir', 'nested', '.env');

        const run = runInChild({
          env: {
            SECUSHARE_DATA_DIR: install.dataDir,
            SECUSHARE_STORAGE_DIR: install.storageDir,
            SECUSHARE_ENV_FILE: unwritableEnvFile,
            __install: install.root
          },
          code: `
            const { getMasterKey } = await import(SERVICES + '/encryptionService.js');
            let outcome;
            try {
              getMasterKey();
              outcome = { threw: false };
            } catch (err) {
              outcome = { threw: true, code: err.code, name: err.name, message: err.message };
            }
            console.log('RESULT:' + JSON.stringify(outcome));
          `
        });

        assert.equal(run.status, 0, `child failed: ${run.stderr}`);
        assert.equal(run.result.threw, true, 'unpersistable key must raise an error');
        assert.equal(run.result.code, 'MASTER_KEY_NOT_PERSISTED');
        assert.ok(
          !/[0-9a-f]{64}/.test(run.result.message),
          'error message must not contain key material'
        );
        assert.equal(fs.existsSync(unwritableEnvFile), false, 'no env file should exist');
      } finally {
        destroyDisposableInstall(install.root);
      }
    });

    await t.test('K4. Existing encrypted install with a missing key fails closed', () => {
      // Seed metadata that references encrypted content, with no key anywhere.
      const install = createDisposableInstall({
        metadataRecords: [
          {
            id: 'existing-record',
            storedName: 'existing.dat',
            status: 'active',
            encryption: { enabled: true, algorithm: 'aes-256-gcm' }
          }
        ],
        storedFiles: []
      });

      try {
        const run = runInChild({
          env: {
            SECUSHARE_DATA_DIR: install.dataDir,
            SECUSHARE_STORAGE_DIR: install.storageDir,
            SECUSHARE_ENV_FILE: install.envFile,
            __install: install.root
          },
          code: `
            const { getMasterKey, inspectEncryptedState } = await import(SERVICES + '/encryptionService.js');
            const state = inspectEncryptedState();
            let outcome;
            try {
              getMasterKey();
              outcome = { threw: false };
            } catch (err) {
              outcome = { threw: true, code: err.code, name: err.name, message: err.message };
            }
            console.log('RESULT:' + JSON.stringify({ state, ...outcome }));
          `
        });

        assert.equal(run.status, 0, `child failed: ${run.stderr}`);
        assert.equal(run.result.state.existing, true, 'install must be detected as existing');
        assert.equal(run.result.threw, true, 'missing key must not be silently replaced');
        assert.equal(run.result.code, 'MASTER_KEY_MISSING');
        assert.equal(
          fs.existsSync(install.envFile),
          false,
          'no replacement key may be written for an existing installation'
        );
      } finally {
        destroyDisposableInstall(install.root);
      }
    });

    await t.test('K5. Existing stored files alone are enough to refuse key generation', () => {
      // No metadata at all, but ciphertext present on disk.
      const install = createDisposableInstall({
        metadataRecords: null,
        storedFiles: ['orphan-ciphertext.dat']
      });

      try {
        const run = runInChild({
          env: {
            SECUSHARE_DATA_DIR: install.dataDir,
            SECUSHARE_STORAGE_DIR: install.storageDir,
            SECUSHARE_ENV_FILE: install.envFile,
            __install: install.root
          },
          code: `
            const { getMasterKey } = await import(SERVICES + '/encryptionService.js');
            let outcome;
            try { getMasterKey(); outcome = { threw: false }; }
            catch (err) { outcome = { threw: true, code: err.code }; }
            console.log('RESULT:' + JSON.stringify(outcome));
          `
        });

        assert.equal(run.status, 0, `child failed: ${run.stderr}`);
        assert.equal(run.result.threw, true);
        assert.equal(run.result.code, 'MASTER_KEY_MISSING');
        assert.equal(fs.existsSync(install.envFile), false);
      } finally {
        destroyDisposableInstall(install.root);
      }
    });

    await t.test('K6. A quoted key in .env resolves to the same bytes as an unquoted key', () => {
      // Regression guard: .env values are commonly quoted, and
      // process.loadEnvFile() strips quotes while a raw file read does not.
      // Both forms must yield an identical key or existing files stop decrypting.
      const disposableHex = crypto.randomBytes(32).toString('hex');

      for (const [label, contents] of [
        ['unquoted', `FILE_ENCRYPTION_MASTER_KEY=${disposableHex}\n`],
        ['double-quoted', `FILE_ENCRYPTION_MASTER_KEY="${disposableHex}"\n`],
        ['single-quoted', `FILE_ENCRYPTION_MASTER_KEY='${disposableHex}'\n`]
      ]) {
        const install = createDisposableInstall({
          metadataRecords: [],
          storedFiles: [],
          envFileContents: contents
        });

        try {
          const run = runInChild({
            env: {
              SECUSHARE_DATA_DIR: install.dataDir,
              SECUSHARE_STORAGE_DIR: install.storageDir,
              SECUSHARE_ENV_FILE: install.envFile,
              __install: install.root
            },
            code: `
              const { getMasterKey } = await import(SERVICES + '/encryptionService.js');
              console.log('RESULT:' + JSON.stringify({ hex: getMasterKey().toString('hex') }));
            `
          });

          assert.equal(run.status, 0, `child failed for ${label}: ${run.stderr}`);
          assert.equal(run.result.hex, disposableHex, `${label} key must resolve identically`);
        } finally {
          destroyDisposableInstall(install.root);
        }
      }
    });

    await t.test('K7. A malformed key is a hard error and is never replaced', () => {
      const install = createDisposableInstall({
        metadataRecords: [],
        storedFiles: [],
        envFileContents: 'FILE_ENCRYPTION_MASTER_KEY=this-is-not-valid-key-material\n'
      });

      try {
        const run = runInChild({
          env: {
            SECUSHARE_DATA_DIR: install.dataDir,
            SECUSHARE_STORAGE_DIR: install.storageDir,
            SECUSHARE_ENV_FILE: install.envFile,
            __install: install.root
          },
          code: `
            const { getMasterKey } = await import(SERVICES + '/encryptionService.js');
            let outcome;
            try { getMasterKey(); outcome = { threw: false }; }
            catch (err) { outcome = { threw: true, message: err.message }; }
            console.log('RESULT:' + JSON.stringify(outcome));
          `
        });

        assert.equal(run.status, 0, `child failed: ${run.stderr}`);
        assert.equal(run.result.threw, true, 'malformed key must raise an error');
        assert.match(run.result.message, /not valid key material/i);

        // The original (wrong) value must still be there, not overwritten.
        const after = fs.readFileSync(install.envFile, 'utf-8');
        assert.match(after, /this-is-not-valid-key-material/);
        assert.equal(
          (after.match(/FILE_ENCRYPTION_MASTER_KEY/g) || []).length,
          1,
          'no additional key entry may be appended'
        );
      } finally {
        destroyDisposableInstall(install.root);
      }
    });

    await t.test('K8. Test-isolation guard refuses to run against real data directories', () => {
      // With the SECUSHARE_* overrides absent, the guard must block.
      const run = runInChild({
        env: {
          SECUSHARE_DATA_DIR: undefined,
          SECUSHARE_STORAGE_DIR: undefined,
          SECUSHARE_ENV_FILE: undefined
        },
        code: `
          const { assertDisposableDataLocations } = await import(SERVICES + '/config.js');
          let outcome;
          try { assertDisposableDataLocations('probe'); outcome = { threw: false }; }
          catch (err) { outcome = { threw: true, message: err.message }; }
          console.log('RESULT:' + JSON.stringify(outcome));
        `
      });

      assert.equal(run.status, 0, `child failed: ${run.stderr}`);
      assert.equal(run.result.threw, true, 'guard must refuse real data locations');
      assert.match(run.result.message, /refuses to run against real application data/);
    });
  });
}
