<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

/**
 * HMAC-based JWT signer (HS256, HS384, HS512).
 *
 * Uses symmetric key for both signing and verification.
 */
final readonly class HmacSigner implements SignerInterface
{
    /**
     * RFC 2104 recommends a key at least as long as the output of the hash.
     * SHA-256 produces 32 bytes; shorter keys measurably weaken HMAC.
     */
    private const int MIN_SECRET_BYTES = 32;

    private Configuration $configuration;

    /**
     * @param string $secret HMAC secret key (raw bytes, minimum 32)
     * @param string $algorithm Algorithm identifier: HS256, HS384, HS512
     */
    public function __construct(
        private string $secret,
        private string $algorithm = 'HS256',
    ) {
        if (strlen($this->secret) < self::MIN_SECRET_BYTES) {
            throw new \InvalidArgumentException(
                sprintf('HMAC secret must be at least %d bytes', self::MIN_SECRET_BYTES),
            );
        }

        $signer = $this->resolveSigner();
        $key = InMemory::plainText($this->secret);

        $this->configuration = Configuration::forSymmetricSigner($signer, $key);
    }

    public function sign(Claims $claims): string
    {
        $builder = $this->configuration->builder()
            ->relatedTo($claims->subject)
            ->issuedAt(new DateTimeImmutable('@' . $claims->issuedAt))
            ->expiresAt(new DateTimeImmutable('@' . $claims->expiresAt));

        if ($claims->issuer !== '') {
            $builder = $builder->issuedBy($claims->issuer);
        }

        if ($claims->audience !== '') {
            $builder = $builder->permittedFor($claims->audience);
        }

        foreach ($claims->custom as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder
            ->getToken($this->configuration->signer(), $this->configuration->signingKey())
            ->toString();
    }

    public function parse(string $token): ?Claims
    {
        try {
            $parsed = $this->configuration->parser()->parse($token);
        } catch (\Throwable) {
            return null;
        }

        if (!$parsed instanceof UnencryptedToken) {
            return null;
        }

        $constraint = new SignedWith(
            $this->configuration->signer(),
            $this->configuration->verificationKey(),
        );

        try {
            $constraint->assert($parsed);
        } catch (\Throwable) {
            return null;
        }

        return $this->extractClaims($parsed);
    }

    private function extractClaims(UnencryptedToken $token): ?Claims
    {
        $claims = $token->claims();

        $subject = $claims->get(RegisteredClaims::SUBJECT);
        $issuedAt = $claims->get(RegisteredClaims::ISSUED_AT);
        $expiresAt = $claims->get(RegisteredClaims::EXPIRATION_TIME);

        if (!is_string($subject) || !$issuedAt instanceof DateTimeImmutable || !$expiresAt instanceof DateTimeImmutable) {
            return null;
        }

        $issuer = $claims->get(RegisteredClaims::ISSUER, '');
        $audience = $claims->get(RegisteredClaims::AUDIENCE, []);
        $notBefore = $claims->get(RegisteredClaims::NOT_BEFORE);

        $custom = [];
        foreach ($claims->all() as $name => $value) {
            if (!in_array($name, RegisteredClaims::ALL, true)) {
                $custom[$name] = $value;
            }
        }

        return new Claims(
            subject: $subject,
            issuedAt: $issuedAt->getTimestamp(),
            expiresAt: $expiresAt->getTimestamp(),
            issuer: is_string($issuer) ? $issuer : '',
            audience: is_array($audience) ? ($audience[0] ?? '') : '',
            notBefore: $notBefore instanceof DateTimeImmutable ? $notBefore->getTimestamp() : null,
            custom: $custom,
        );
    }

    private function resolveSigner(): Hmac
    {
        return match ($this->algorithm) {
            'HS256' => new Hmac\Sha256(),
            'HS384' => new Hmac\Sha384(),
            'HS512' => new Hmac\Sha512(),
            default => throw new \InvalidArgumentException(
                sprintf('Unsupported HMAC algorithm: %s. Supported: HS256, HS384, HS512', $this->algorithm),
            ),
        };
    }
}
