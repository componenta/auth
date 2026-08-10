#!/usr/bin/env bash
set -euo pipefail

composer validate --strict
composer check-platform-reqs
composer lint
composer test
composer phpstan
composer audit --no-interaction
