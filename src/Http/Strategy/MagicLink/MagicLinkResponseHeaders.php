<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

use Psr\Http\Message\ResponseInterface;

/** Prevents a URL-borne magic-link bearer from becoming a downstream referrer. */
final class MagicLinkResponseHeaders
{
    private function __construct() {}

    public static function apply(ResponseInterface $response): ResponseInterface
    {
        return $response->withHeader('Referrer-Policy', 'no-referrer');
    }
}
