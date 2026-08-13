# MySQL storage contract

`schema.sql` is the canonical MySQL 8.4 schema for the built-in Componenta Auth SQL stores. The constraints and indexes are part of the runtime contract, not optional tuning hints.

Important properties:

- credential identifiers use byte-exact/binary collations so case-sensitive application identities and bearer material are not collapsed by MySQL collation rules;
- one-time-token tables enforce one active row per subject with `UNIQUE(user_id)` and unique stored token hashes;
- OTP uses one row per destination and an expiry index for bounded cleanup;
- session and remember-me tables include lineage/revocation and cleanup indexes;
- refresh family IDs support the full 32–64 byte generator range (`64–128` hex characters);
- refresh tokens use `(family_id, expires_at)` for the final family-expiry recheck;
- `refresh_token_families.cleanup_after` is an indexed housekeeping cache. It is not trusted as security state: the housekeeper always serializes on the family row and recomputes the latest token expiry on the primary before deletion.

For a custom schema, preserve equivalent PK/UNIQUE/FK, binary-comparison and index properties even when table or column names differ.

Existing v2 installations may add the optional indexed refresh cleanup cache without changing token semantics:

```sql
ALTER TABLE refresh_token_families
  MODIFY family_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  ADD cleanup_after BIGINT UNSIGNED NULL,
  ADD INDEX idx_refresh_family_cleanup (cleanup_after, family_id);

ALTER TABLE refresh_tokens
  MODIFY family_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  ADD INDEX idx_refresh_token_family_expiry (family_id, expires_at);
```

Pass `cleanupAfterColumn: 'cleanup_after'` in `DatabaseRefreshTokenStoreConfig` (the Componenta config factory uses this name by default). Old direct-construction schemas without that column remain supported; the housekeeper falls back to the safe aggregate candidate query, but that fallback does not have the same bounded-scan characteristics.
