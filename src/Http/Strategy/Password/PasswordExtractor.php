<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class PasswordExtractor implements PayloadExtractorInterface
{
    private const int MAX_IDENTITY_LENGTH = 320;
    private const int MAX_PASSWORD_LENGTH = 4096;

    public function __construct(
        public string $identityField = 'email',
        public string $passwordField = 'password',
        public string $rememberField = 'remember',
        public bool $normalizeIdentity = true,
    ) {}

    public function extract(ServerRequestInterface $request): Payload
    {
        $body = $request->getParsedBody();
        if (!is_array($body)) {
            throw InvalidPayloadException::invalidField('body');
        }

        if (!array_key_exists($this->identityField, $body)) {
            throw InvalidPayloadException::missingField($this->identityField);
        }
        if (!array_key_exists($this->passwordField, $body)) {
            throw InvalidPayloadException::missingField($this->passwordField);
        }

        $identity = $body[$this->identityField];
        $password = $body[$this->passwordField];

        if (!is_string($identity) || $identity === '' || strlen($identity) > self::MAX_IDENTITY_LENGTH) {
            throw InvalidPayloadException::invalidField($this->identityField);
        }
        if (!is_string($password) || $password === '' || strlen($password) > self::MAX_PASSWORD_LENGTH) {
            throw InvalidPayloadException::invalidField($this->passwordField);
        }

        if ($this->normalizeIdentity) {
            $identity = strtolower(trim($identity));
            if ($identity === '') {
                throw InvalidPayloadException::invalidField($this->identityField);
            }
        }

        return new Payload(
            identity: $identity,
            password: $password,
            remember: $this->parseBoolean($body[$this->rememberField] ?? false),
        );
    }

    private function parseBoolean(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value) && ($value === 0 || $value === 1)) {
            return $value === 1;
        }
        if (is_string($value)) {
            return match (strtolower(trim($value))) {
                '', '0', 'false', 'off', 'no' => false,
                '1', 'true', 'on', 'yes' => true,
                default => throw InvalidPayloadException::invalidField($this->rememberField),
            };
        }

        throw InvalidPayloadException::invalidField($this->rememberField);
    }
}
