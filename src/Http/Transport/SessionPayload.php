<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Transport;

/**
 * Payload for session-based authentication.
 *
 * Used for both extraction (session cookie -> sessionId)
 * and storage (sessionId + optional remember-me token -> cookies).
 */
final readonly class SessionPayload
{
    public function __construct(
        public ?string $sessionId = null,
        public ?string $rememberMeToken = null,
    ) {}
}
