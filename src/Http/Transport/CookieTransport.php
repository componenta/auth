<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Transport;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\TransportInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/** Cookie transport for session and optional persistent remember-me credentials. */
final readonly class CookieTransport implements TransportInterface
{
    private const int MAX_SESSION_ID_LENGTH = 512;
    private const int MAX_REMEMBER_ME_TOKEN_LENGTH = 4096;
    private const int MAX_COOKIE_PATH_LENGTH = 1024;
    private const int MAX_COOKIE_DOMAIN_LENGTH = 253;

    public string $sameSite;

    public function __construct(
        public string $name = 'sid',
        public string $path = '/',
        public string $domain = '',
        public bool $secure = true,
        public bool $httpOnly = true,
        string $sameSite = 'Lax',
        public int $ttl = 0,
        public string $rememberMeName = '',
        public int $rememberMeTtl = 2592000,
    ) {
        self::assertCookieName($this->name, 'Session cookie');

        if ($this->rememberMeName !== '') {
            self::assertCookieName($this->rememberMeName, 'Remember-me cookie');

            if ($this->rememberMeName === $this->name) {
                throw new \InvalidArgumentException(
                    'Session and remember-me cookie names must be different.',
                );
            }
        }

        if (
            $this->path === ''
            || strlen($this->path) > self::MAX_COOKIE_PATH_LENGTH
            || $this->path[0] !== '/'
            || preg_match('/[\x00-\x1F\x7F;]/', $this->path) === 1
        ) {
            throw new \InvalidArgumentException(
                'Cookie path must start with "/" and contain no control characters or semicolons.',
            );
        }

        if (
            strlen($this->domain) > self::MAX_COOKIE_DOMAIN_LENGTH
            || preg_match('/[\x00-\x20\x7F;,\/\\\\]/', $this->domain) === 1
        ) {
            throw new \InvalidArgumentException('Cookie domain is invalid.');
        }

        $this->sameSite = match (strtolower($sameSite)) {
            'lax' => 'Lax',
            'strict' => 'Strict',
            'none' => 'None',
            default => throw new \InvalidArgumentException(
                'SameSite must be one of Lax, Strict or None.',
            ),
        };

        if ($this->sameSite === 'None' && !$this->secure) {
            throw new \InvalidArgumentException(
                'SameSite=None requires Secure cookies.',
            );
        }

        if ($this->ttl < 0) {
            throw new \InvalidArgumentException(
                'Session cookie TTL must be greater than or equal to zero.',
            );
        }

        if ($this->rememberMeName !== '' && $this->rememberMeTtl < 1) {
            throw new \InvalidArgumentException(
                'Remember-me cookie TTL must be greater than zero.',
            );
        }

        $this->assertPrefixRequirements($this->name);

        if ($this->rememberMeName !== '') {
            $this->assertPrefixRequirements($this->rememberMeName);
        }
    }

    #[\Override]
    public function extract(ServerRequestInterface $request): ?object
    {
        /** @var array<string, mixed> $cookies */
        $cookies = $request->getCookieParams();
        $sessionId = $this->readCredential(
            $cookies,
            $this->name,
            self::MAX_SESSION_ID_LENGTH,
        );
        $rememberMeToken = $this->rememberMeName === ''
            ? null
            : $this->readCredential(
                $cookies,
                $this->rememberMeName,
                self::MAX_REMEMBER_ME_TOKEN_LENGTH,
            );

        if ($sessionId === null && $rememberMeToken === null) {
            return null;
        }

        return new SessionPayload($sessionId, $rememberMeToken);
    }

    #[\Override]
    public function store(
        ServerRequestInterface $request,
        ResponseInterface $response,
        object $payload,
    ): ResponseInterface {
        if (!$payload instanceof SessionPayload) {
            return $response;
        }

        if ($payload->sessionId !== null) {
            self::assertCredential(
                $payload->sessionId,
                $this->name,
                self::MAX_SESSION_ID_LENGTH,
            );
            $response = $this->withSetCookie(
                $response,
                $this->name,
                $this->buildCookie($this->name, $payload->sessionId, $this->ttl),
            );
        }

        if ($payload->rememberMeToken !== null && $this->rememberMeName !== '') {
            self::assertCredential(
                $payload->rememberMeToken,
                $this->rememberMeName,
                self::MAX_REMEMBER_ME_TOKEN_LENGTH,
            );
            $response = $this->withSetCookie(
                $response,
                $this->rememberMeName,
                $this->buildCookie(
                    $this->rememberMeName,
                    $payload->rememberMeToken,
                    $this->rememberMeTtl,
                ),
            );
        }

        return $response;
    }

    #[\Override]
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

    /** @param array<string, mixed> $cookies */
    private function readCredential(
        array $cookies,
        string $name,
        int $maxLength,
    ): ?string
    {
        if (!array_key_exists($name, $cookies)) {
            return null;
        }

        $value = $cookies[$name];

        if (
            !is_string($value)
            || strlen($value) > $maxLength
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw InvalidPayloadException::invalidField($name);
        }

        return $value === '' ? null : $value;
    }

    private static function assertCookieName(string $name, string $label): void
    {
        if (
            $name === ''
            || preg_match('/^[!#$%&\'\*+\-.^_`|~0-9A-Za-z]+$/', $name) !== 1
        ) {
            throw new \InvalidArgumentException($label . ' name is invalid.');
        }
    }

    private static function assertCredential(
        string $value,
        string $name,
        int $maxLength,
    ): void {
        if (
            $value === ''
            || strlen($value) > $maxLength
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new \InvalidArgumentException(sprintf(
                'Credential for cookie "%s" must contain between 1 and %d bytes.',
                $name,
                $maxLength,
            ));
        }
    }

    private function assertPrefixRequirements(string $name): void
    {
        if (str_starts_with($name, '__Secure-') && !$this->secure) {
            throw new \InvalidArgumentException(
                '__Secure- cookie names require Secure=true.',
            );
        }

        if (
            str_starts_with($name, '__Host-')
            && (!$this->secure || $this->domain !== '' || $this->path !== '/')
        ) {
            throw new \InvalidArgumentException(
                '__Host- cookie names require Secure=true, Path=/ and an empty Domain.',
            );
        }
    }

    private function withSetCookie(
        ResponseInterface $response,
        string $cookieName,
        string $cookieString,
    ): ResponseInterface {
        $existing = $response->getHeader('Set-Cookie');
        $filtered = array_filter(
            $existing,
            static fn(string $header): bool => !str_starts_with(
                $header,
                $cookieName . '=',
            ),
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
            $parts[] = sprintf(
                'Expires=%s',
                gmdate('D, d M Y H:i:s T', time() + $ttl),
            );
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
