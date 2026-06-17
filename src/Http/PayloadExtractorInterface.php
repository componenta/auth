<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Componenta\Auth\Exception\InvalidPayloadException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Extracts authentication payload from an HTTP request.
 *
 * Implementations handle different authentication mechanisms:
 * - PasswordExtractor: email/password from request body
 * - BearerExtractor: token from Authorization header
 * - CookieTransport: session ID from cookies
 *
 * Extractor responsibilities:
 * - Extract data from request
 * - Verify data completeness
 * - Normalize data if needed (e.g., trim, lowercase for identity fields)
 *
 * Extractor does NOT:
 * - Validate data format (e.g., valid email) - strategy responsibility
 * - Perform business validation (e.g., user exists) - strategy responsibility
 *
 * Behavior:
 * - Returns null if authentication data is not present
 *   (e.g., none of the expected fields exist)
 * - Throws InvalidPayloadException if data is present but incomplete
 *   (e.g., email exists but password is missing)
 *
 * If the extractor also implements PayloadStorageInterface
 * (i.e., is a TransportInterface), it manages client-side storage
 * (e.g., via cookies).
 *
 * Stateless extractors (BearerExtractor, ApiKeyExtractor)
 * do not implement Storage - the client manages the token.
 */
interface PayloadExtractorInterface
{
    /**
     * Extracts authentication payload from the request.
     *
     * @param ServerRequestInterface $request The HTTP request
     * @return object|null The payload or null if data is not present
     *
     * @throws InvalidPayloadException If data is incomplete
     */
    public function extract(ServerRequestInterface $request): ?object;
}
