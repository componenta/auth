<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

/** Shared syntax and size contract for HTTP bearer credentials. */
final class BearerCredential
{
    public const int MAX_LENGTH = 8192;

    private function __construct() {}

    public static function isValid(string $token): bool
    {
        return $token !== ''
            && strlen($token) <= self::MAX_LENGTH
            && preg_match('/\A[A-Za-z0-9\-._~+\/]+=*\z/D', $token) === 1;
    }

    public static function assertValid(
        #[\SensitiveParameter]
        string $token,
    ): void {
        if (!self::isValid($token)) {
            throw new \InvalidArgumentException('Bearer token is invalid.');
        }
    }
}
