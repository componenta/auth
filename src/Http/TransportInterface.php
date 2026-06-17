<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

/**
 * Combined extractor and storage for stateful authentication.
 *
 * Transports handle the full lifecycle of authentication tokens:
 * - Extract: read session/token from incoming request
 * - Store: write session/token to outgoing response
 * - Remove: clear session/token on logout
 *
 * Common implementations:
 * - CookieTransport: HttpOnly session cookies
 */
interface TransportInterface extends PayloadExtractorInterface, PayloadStorageInterface
{
}
