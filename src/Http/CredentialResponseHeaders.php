<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Psr\Http\Message\ResponseInterface;

/** Prevents responses carrying credential mutations from being cached. */
final class CredentialResponseHeaders
{
    private function __construct() {}

    public static function apply(ResponseInterface $response): ResponseInterface
    {
        return $response
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
