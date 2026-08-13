<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Extractor;

/** Shared bearer-token transport profile used by extractors and JWT signers. */
final class BearerToken
{
    public const int MAX_LENGTH = 8192;

    private function __construct() {}

    public static function valid(string $token): bool
    {
        return $token !== ''
            && strlen($token) <= self::MAX_LENGTH
            && preg_match('/\A[A-Za-z0-9\-._~+\/]+=*\z/D', $token) === 1;
    }

    public static function assert(string $token): string
    {
        if (!self::valid($token)) {
            throw new \InvalidArgumentException(sprintf(
                'Bearer token must contain between 1 and %d transport-safe bytes.',
                self::MAX_LENGTH,
            ));
        }

        return $token;
    }
}
