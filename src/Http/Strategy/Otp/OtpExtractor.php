<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class OtpExtractor implements PayloadExtractorInterface
{
    private const int MAX_DESTINATION_LENGTH = 320;
    private const int MAX_CODE_LENGTH = 128;

    public function __construct(
        public string $destinationField = 'destination',
        public string $codeField = 'code',
    ) {}

    public function extract(ServerRequestInterface $request): ?OtpPayload
    {
        $body = $request->getParsedBody();
        if (!is_array($body)) {
            throw InvalidPayloadException::invalidField('body');
        }

        $destination = $body[$this->destinationField] ?? null;
        $code = $body[$this->codeField] ?? null;
        if ($destination === null || $destination === '' || $code === null || $code === '') {
            return null;
        }
        if (!is_string($destination) || strlen($destination) > self::MAX_DESTINATION_LENGTH) {
            throw InvalidPayloadException::invalidField($this->destinationField);
        }
        if (!is_string($code) || strlen($code) > self::MAX_CODE_LENGTH) {
            throw InvalidPayloadException::invalidField($this->codeField);
        }

        return new OtpPayload($destination, $code);
    }
}
