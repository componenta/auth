<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Componenta\Auth\Exception\TransportException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Stores and removes authentication payload in HTTP responses.
 *
 * Used to persist authentication state (e.g., session cookies)
 * after successful authentication or to clear it on logout.
 */
interface PayloadStorageInterface
{
    /**
     * Stores the payload in the response.
     *
     * Typically adds a Set-Cookie header for session-based auth
     * or returns token data in the response body.
     *
     * @param ServerRequestInterface $request The HTTP request
     * @param ResponseInterface $response The HTTP response to modify
     * @param object $payload The payload to store
     * @return ResponseInterface The modified response
     *
     * @throws TransportException On storage failure
     */
    public function store(
        ServerRequestInterface $request,
        ResponseInterface $response,
        object $payload,
    ): ResponseInterface;

    /**
     * Removes the payload from the response.
     *
     * Typically clears the session cookie or invalidates the token.
     *
     * @param ServerRequestInterface $request The HTTP request
     * @param ResponseInterface $response The HTTP response to modify
     * @return ResponseInterface The modified response
     *
     * @throws TransportException On removal failure
     */
    public function remove(
        ServerRequestInterface $request,
        ResponseInterface $response,
    ): ResponseInterface;
}
