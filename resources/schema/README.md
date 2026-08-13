# Built-in SQL store schema contract

`mysql-8.4.sql` is the canonical MySQL 8.4/InnoDB schema for the built-in
`componenta/auth` SQL stores. The table and column names may be changed through
package configuration, but the constraints, compatible column widths,
case-sensitivity and indexes are part of the store contract rather than merely
example tuning.

## Required invariants

- session IDs and OTP destinations are compared byte-for-byte; use a binary
  collation when storing them;
- remember-me and one-time bearer representations are unique;
- one-time token tables have one row per subject because
  `TokenManager::replaceForSubject()` is implemented as an upsert on the subject
  column;
- OTP destinations are unique and challenge IDs are unique;
- refresh token hashes are unique, refresh family IDs accept the full 64-128
  hexadecimal characters supported by `RefreshTokenGenerator`, and token rows
  reference an existing family;
- `refresh_token_families.expires_at` stores the maximum expiry of every token
  ever issued in that family. Rotation extends it inside the same transaction
  that consumes the presented token and creates the successor. Housekeeping
  selects candidates through the index on this field and rechecks state under
  the family serialization lock before deletion;
- expiry/cleanup predicates have supporting indexes. Cleanup limits bound the
  number of mutations; these indexes prevent routine candidate discovery from
  degenerating into avoidable full-table scans.

## Upgrading an existing v2 schema

Before deploying code that uses the current default `DatabaseRefreshTokenStore`,
add `refresh_token_families.expires_at BIGINT UNSIGNED NOT NULL`, backfill it to
the maximum `refresh_tokens.expires_at` for each family, add an index on it, and
widen `family_id` to `VARCHAR(128)` in both refresh tables when a narrower type
was used previously. The foreign-key columns must remain type/collation
compatible.

Also add the cleanup indexes shown in `mysql-8.4.sql`. If existing session IDs or
OTP destinations were stored under a case-insensitive collation, migrate them to
a binary collation only after checking for values that would collide under the
new comparison semantics.

Magic-link and password-reset managers should use separate purpose-specific
one-time-token tables as shown. Purpose is cryptographically domain-separated in
the stored hash, but a shared subject-unique table would still make issuance in
one purpose replace the other purpose's row.
