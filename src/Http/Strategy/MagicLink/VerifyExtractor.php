<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Extracts magic link token from the request.
 *
 * Checks query parameters first (GET - user clicks a link),
 * then request body (POST - form submission).
 */
final readonly class VerifyExtractor implements PayloadExtractorInterface
{
    public function __construct(
        public string $tokenField = 'token',
    ) {}

    public function extract(ServerRequestInterface $request): ?VerifyPayload
    {
        $token = $request->getQueryParams()[$this->tokenField] ?? null;

        if ($token === null) {
            $body = $request->getParsedBody() ?? [];

            if (!is_array($body)) {
                $body = get_object_vars($body);
            }

            $token = $body[$this->tokenField] ?? null;
        }

        if ($token === null || $token === '') {
            return null;
        }

        return new VerifyPayload($token);
    }
}
