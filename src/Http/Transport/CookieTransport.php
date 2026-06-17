<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Transport;

use Componenta\Auth\Http\TransportInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Cookie-based transport for session authentication.
 *
 * Handles session cookie (browser session, ttl=0) and optionally
 * remember-me cookie (persistent, configurable ttl).
 */
final readonly class CookieTransport implements TransportInterface
{
    /**
     * @param string $name Session cookie name
     * @param string $path Cookie path
     * @param string $domain Cookie domain (empty = current domain only)
     * @param bool $secure Send only over HTTPS
     * @param bool $httpOnly Prevent JavaScript access
     * @param string $sameSite SameSite policy (Lax, Strict, None)
     * @param int $ttl Session cookie lifetime (0 = browser session)
     * @param string $rememberMeName Remember-me cookie name (empty = disabled)
     * @param int $rememberMeTtl Remember-me cookie lifetime in seconds
     */
    public function __construct(
        public string $name = 'sid',
        public string $path = '/',
        public string $domain = '',
        public bool $secure = true,
        public bool $httpOnly = true,
        public string $sameSite = 'Lax',
        public int $ttl = 0,
        public string $rememberMeName = '',
        public int $rememberMeTtl = 2592000,
    ) {}

    public function extract(ServerRequestInterface $request): ?object
    {
        $cookies = $request->getCookieParams();

        $sessionId = $cookies[$this->name] ?? null;
        $rememberMeToken = ($this->rememberMeName !== '')
            ? ($cookies[$this->rememberMeName] ?? null)
            : null;

        if ($sessionId === '') {
            $sessionId = null;
        }

        if ($rememberMeToken === '') {
            $rememberMeToken = null;
        }

        if ($sessionId === null && $rememberMeToken === null) {
            return null;
        }

        return new SessionPayload($sessionId, $rememberMeToken);
    }

    public function store(
        ServerRequestInterface $request,
        ResponseInterface $response,
        object $payload,
    ): ResponseInterface {
        if (!$payload instanceof SessionPayload) {
            return $response;
        }

        // Session cookie
        if ($payload->sessionId !== null) {
            $response = $this->withSetCookie(
                $response,
                $this->name,
                $this->buildCookie($this->name, $payload->sessionId, $this->ttl),
            );
        }

        // Remember-me cookie
        if ($payload->rememberMeToken !== null && $this->rememberMeName !== '') {
            $response = $this->withSetCookie(
                $response,
                $this->rememberMeName,
                $this->buildCookie($this->rememberMeName, $payload->rememberMeToken, $this->rememberMeTtl),
            );
        }

        return $response;
    }

    public function remove(
        ServerRequestInterface $request,
        ResponseInterface $response,
    ): ResponseInterface {
        $response = $this->withSetCookie(
            $response,
            $this->name,
            $this->buildCookie($this->name, '', -3600),
        );

        if ($this->rememberMeName !== '') {
            $response = $this->withSetCookie(
                $response,
                $this->rememberMeName,
                $this->buildCookie($this->rememberMeName, '', -3600),
            );
        }

        return $response;
    }

    /**
     * Replaces any existing Set-Cookie header for the same cookie name,
     * preventing duplicate headers when multiple middleware layers
     * set the same cookie (e.g. chain-follow + remember-me auto-login).
     */
    private function withSetCookie(
        ResponseInterface $response,
        string $cookieName,
        string $cookieString,
    ): ResponseInterface {
        $existing = $response->getHeader('Set-Cookie');

        $filtered = array_filter(
            $existing,
            static fn(string $header): bool => !str_starts_with($header, $cookieName . '='),
        );

        $response = $response->withoutHeader('Set-Cookie');

        foreach ($filtered as $header) {
            $response = $response->withAddedHeader('Set-Cookie', $header);
        }

        return $response->withAddedHeader('Set-Cookie', $cookieString);
    }

    private function buildCookie(string $name, string $value, int $ttl): string
    {
        $parts = [
            sprintf('%s=%s', $name, rawurlencode($value)),
            sprintf('Path=%s', $this->path),
            sprintf('SameSite=%s', $this->sameSite),
        ];

        if ($ttl !== 0) {
            $expires = time() + $ttl;
            $parts[] = sprintf('Expires=%s', gmdate('D, d M Y H:i:s T', $expires));
            $parts[] = sprintf('Max-Age=%d', max(0, $ttl));
        }

        if ($this->domain !== '') {
            $parts[] = sprintf('Domain=%s', $this->domain);
        }

        if ($this->secure) {
            $parts[] = 'Secure';
        }

        if ($this->httpOnly) {
            $parts[] = 'HttpOnly';
        }

        return implode('; ', $parts);
    }
}
