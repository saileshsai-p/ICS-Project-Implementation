#!/usr/bin/env node

/**
 * Migration CLI Script
 * Upgrades legacy plaintext records to Version 2 (AES-256-GCM encrypted + SHA-256 integrity).
 * Usage: node scripts/migrate.js
 */

import { migrateAllLegacyRecords } from '../services/migrationService.js';
import { initStorage } from '../services/fileService.js';
import { initMetadataStore } from '../services/metadataService.js';

async function run() {
  console.log('--- SecuShare Version 2 Storage Migration ---');
  await initStorage();
  await initMetadataStore();

  try {
    const result = await migrateAllLegacyRecords();
    console.log(`Scan completed:`);
    console.log(`- Total records: ${result.total}`);
    console.log(`- Migrated records: ${result.migratedCount}`);
    console.log(`- Skipped records: ${result.skippedCount}`);
    if (result.errors.length > 0) {
      console.warn(`- Errors encountered (${result.errors.length}):`);
      for (const err of result.errors) {
        console.warn(`  [${err.id}]: ${err.error}`);
      }
    }
  } catch (err) {
    console.error('Fatal migration error:', err.message);
    process.exit(1);
  }
}

run();
