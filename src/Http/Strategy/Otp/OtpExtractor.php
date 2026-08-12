<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class OtpExtractor implements PayloadExtractorInterface
{
    private const int MAX_DESTINATION_LENGTH = 320;

    public function __construct(
        private OtpConfig $config,
        public string $destinationField = 'destination',
        public string $codeField = 'code',
    ) {
        foreach ([
            'destination' => $this->destinationField,
            'code' => $this->codeField,
        ] as $name => $field) {
            if (preg_match('/\A[A-Za-z_][A-Za-z0-9_.-]*\z/D', $field) !== 1) {
                throw new \InvalidArgumentException(sprintf(
                    'OTP %s field name is invalid.',
                    $name,
                ));
            }
        }

        if ($this->destinationField === $this->codeField) {
            throw new \InvalidArgumentException('OTP destination and code fields must be different.');
        }
    }

    #[\Override]
    public function extract(ServerRequestInterface $request): ?OtpPayload
    {
        $body = $request->getParsedBody();

        if ($body === null) {
            return null;
        }

        if (!is_array($body)) {
            throw InvalidPayloadException::invalidField('body');
        }

        $hasDestination = array_key_exists($this->destinationField, $body);
        $hasCode = array_key_exists($this->codeField, $body);

        if (!$hasDestination && !$hasCode) {
            return null;
        }

        if (!$hasDestination) {
            throw InvalidPayloadException::missingField($this->destinationField);
        }

        if (!$hasCode) {
            throw InvalidPayloadException::missingField($this->codeField);
        }

        $destination = $body[$this->destinationField];
        $code = $body[$this->codeField];

        if (
            !is_string($destination)
            || $destination === ''
            || strlen($destination) > self::MAX_DESTINATION_LENGTH
            || trim($destination) !== $destination
            || preg_match('/[\x00-\x1F\x7F]/', $destination) === 1
        ) {
            throw InvalidPayloadException::invalidField($this->destinationField);
        }

        if (
            !is_string($code)
            || preg_match(sprintf(
                '/\A[0-9]{%d}\z/D',
                $this->config->length,
            ), $code) !== 1
        ) {
            throw InvalidPayloadException::invalidField($this->codeField);
        }

        return new OtpPayload($destination, $code);
    }
}
