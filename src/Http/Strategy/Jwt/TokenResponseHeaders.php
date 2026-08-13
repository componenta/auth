<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Psr\Http\Message\ResponseInterface;

final class TokenResponseHeaders
{
    private function __construct() {}

    public static function apply(ResponseInterface $response): ResponseInterface
    {
        $response = $response
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');

        return $response->getBody()->getSize() === 0
            ? $response->withoutHeader('Content-Type')
            : $response->withHeader('Content-Type', 'application/json');
    }
}
