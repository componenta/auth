<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

/**
 * RSA-based JWT signer (RS256, RS384, RS512).
 *
 * Uses asymmetric keys: private key for signing,
 * public key for verification. If private key is not
 * provided, the signer operates in verify-only mode.
 */
final readonly class RsaSigner implements SignerInterface
{
    private Configuration $configuration;

    /**
     * @param string $publicKey PEM-encoded public key or file path
     * @param string|null $privateKey PEM-encoded private key or file path (null = verify-only)
     * @param string $passphrase Private key passphrase
     * @param string $algorithm Algorithm identifier: RS256, RS384, RS512
     */
    public function __construct(
        private string $publicKey,
        private ?string $privateKey = null,
        private string $passphrase = '',
        private string $algorithm = 'RS256',
    ) {
        if ($this->publicKey === '') {
            throw new \InvalidArgumentException('Public key must not be empty');
        }

        $signer = $this->resolveSigner();
        $verificationKey = $this->resolveKey($this->publicKey);
        $signingKey = $this->privateKey !== null
            ? $this->resolveKey($this->privateKey, $this->passphrase)
            : $verificationKey;

        $this->configuration = Configuration::forAsymmetricSigner(
            $signer,
            $signingKey,
            $verificationKey,
        );
    }

    public function sign(Claims $claims): string
    {
        if ($this->privateKey === null) {
            throw new \LogicException('Cannot sign without a private key');
        }

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

    private function resolveKey(string $key, string $passphrase = ''): InMemory
    {
        if (str_starts_with($key, 'file://')) {
            return InMemory::file($key, $passphrase);
        }

        return InMemory::plainText($key, $passphrase);
    }

    private function resolveSigner(): Rsa
    {
        return match ($this->algorithm) {
            'RS256' => new Rsa\Sha256(),
            'RS384' => new Rsa\Sha384(),
            'RS512' => new Rsa\Sha512(),
            default => throw new \InvalidArgumentException(
                sprintf('Unsupported RSA algorithm: %s. Supported: RS256, RS384, RS512', $this->algorithm),
            ),
        };
    }
}
