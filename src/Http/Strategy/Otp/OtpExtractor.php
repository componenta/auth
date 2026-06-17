<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Extracts OTP verification payload from the request body.
 *
 * Expects both destination and code fields in the parsed body.
 * Returns null if either field is missing or empty.
 */
final readonly class OtpExtractor implements PayloadExtractorInterface
{
    public function __construct(
        public string $destinationField = 'destination',
        public string $codeField = 'code',
    ) {}

    public function extract(ServerRequestInterface $request): ?OtpPayload
    {
        $body = $request->getParsedBody() ?? [];

        if (!is_array($body)) {
            $body = get_object_vars($body);
        }

        $destination = $body[$this->destinationField] ?? null;
        $code = $body[$this->codeField] ?? null;

        if ($destination === null || $destination === '' || $code === null || $code === '') {
            return null;
        }

        return new OtpPayload($destination, $code);
    }
}
