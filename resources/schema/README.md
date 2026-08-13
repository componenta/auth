# Built-in SQL store schema contract

`mysql-8.4.sql` is the canonical MySQL 8.4/InnoDB schema for the built-in
`componenta/auth` SQL stores. The table and column names may be changed through
package configuration, but the constraints, compatible column widths,
byte-comparison semantics and indexes are part of the store contract rather
than merely example tuning.

## Required invariants

- opaque session IDs, session lineage IDs, User-Agent bytes and OTP destinations
  are stored byte-for-byte. The public contracts do not require UTF-8, so the
  reference schema uses `VARBINARY` rather than a text collation for these
  values;
- UUIDs, hexadecimal hashes and refresh family IDs use byte-exact `ascii_bin`
  comparison;
- remember-me and one-time bearer representations are unique;
- one-time token tables have one row per subject because
  `TokenManager::replaceForSubject()` is implemented as an upsert on the subject
  column;
- OTP destinations are unique and challenge IDs are unique;
- refresh token hashes are unique, refresh family IDs accept the full 64-128
  hexadecimal characters supported by `RefreshTokenGenerator`, and token rows
  reference an existing family;
- `refresh_token_families.expires_at` stores the maximum expiry of every token
  issued in that family. Rotation extends it inside the same transaction that
  consumes the presented token and creates the successor. Expired token-history
  rows may be pruned after their own `expires_at` without reducing the family
  deadline: replay detection is required only while the bearer itself remains
  unexpired. Housekeeping serializes each history deletion through the family
  row, selects terminal family candidates through the family-expiry index, and
  deletes a family only after its bounded history drain has left no token rows;
- expiry/cleanup predicates have supporting indexes. In particular,
  `idx_refresh_token_expiry` supports bounded pruning from live sliding refresh
  families. Cleanup limits bound mutation fan-out; these indexes prevent routine
  candidate discovery from degenerating into avoidable full-table scans.

## Upgrading an existing v2 schema

Before deploying code that uses the current default `DatabaseRefreshTokenStore`,
add `refresh_token_families.expires_at BIGINT UNSIGNED NOT NULL`, backfill it to
the maximum `refresh_tokens.expires_at` for each family, add an index on it, and
widen `family_id` to `VARCHAR(128)` in both refresh tables when a narrower type
was used previously. The foreign-key columns must remain type/collation
compatible.

Also add every cleanup index shown in `mysql-8.4.sql`, including
`idx_refresh_token_expiry`. Existing textual session and remember-me lineage
columns can be migrated to `VARBINARY(512)` without changing their bytes. OTP
destinations can likewise be migrated to `VARBINARY(320)`. Check for collisions
before changing any previously case-insensitive key column to byte-exact
comparison semantics.

Magic-link and password-reset managers should use separate purpose-specific
one-time-token tables as shown. Purpose is cryptographically domain-separated in
the stored hash, but a shared subject-unique table would still make issuance in
one purpose replace the other purpose's row.
