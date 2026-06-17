<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Extracts email/password credentials from request body.
 *
 * Normalizes identity field (trim, lowercase) by default.
 */
final readonly class PasswordExtractor implements PayloadExtractorInterface
{
    /**
     * @param string $identityField Field name for identity (email, username)
     * @param string $passwordField Field name for password
     * @param bool $normalizeIdentity Whether to normalize identity (trim, lowercase)
     */
    public function __construct(
        public string $identityField = 'email',
        public string $passwordField = 'password',
        public string $rememberField = 'remember',
        public bool $normalizeIdentity = true,
    ) {}

    public function extract(ServerRequestInterface $request): Payload
    {
        $body = $request->getParsedBody() ?? [];

        if (!is_array($body)) {
            $body = get_object_vars($body);
        }

        $identity = $body[$this->identityField] ?? null;
        $password = $body[$this->passwordField] ?? null;

        // Incomplete data - error
        if ($identity === null) {
            throw InvalidPayloadException::missingField($this->identityField);
        }

        if ($password === null) {
            throw InvalidPayloadException::missingField($this->passwordField);
        }

        if ($this->normalizeIdentity) {
            $identity = strtolower(trim($identity));
        }

        $remember = (bool) ($body[$this->rememberField] ?? false);

        return new Payload($identity, $password, $remember);
    }
}
