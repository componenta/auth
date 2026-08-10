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

final readonly class RsaSigner implements SignerInterface
{
    private Configuration $configuration;
    private bool $canSign;

    public function __construct(
        string $publicKey,
        #[\SensitiveParameter]
        ?string $privateKey = null,
        #[\SensitiveParameter]
        string $passphrase = '',
        string $algorithm = 'RS256',
    ) {
        if ($publicKey === '') {
            throw new \InvalidArgumentException('Public key must not be empty.');
        }

        $signer = self::resolveSigner($algorithm);
        $verificationKey = self::resolveKey($publicKey);
        $signingKey = $privateKey !== null
            ? self::resolveKey($privateKey, $passphrase)
            : $verificationKey;
        $this->configuration = Configuration::forAsymmetricSigner(
            $signer,
            $signingKey,
            $verificationKey,
        );
        $this->canSign = $privateKey !== null;
    }

    #[\Override]
    public function sign(Claims $claims): string
    {
        if (!$this->canSign) {
            throw new \LogicException('Cannot sign without a private key.');
        }

        $builder = $this->configuration->builder()
            ->withHeader('typ', $claims->type)
            ->relatedTo($claims->subject)
            ->issuedBy($claims->issuer)
            ->permittedFor($claims->audience)
            ->issuedAt(new DateTimeImmutable('@' . $claims->issuedAt))
            ->expiresAt(new DateTimeImmutable('@' . $claims->expiresAt));

        if ($claims->notBefore !== null) {
            $builder = $builder->canOnlyBeUsedAfter(
                new DateTimeImmutable('@' . $claims->notBefore),
            );
        }

        foreach ($claims->custom as $name => $value) {
            if (in_array($name, RegisteredClaims::ALL, true)) {
                throw new \InvalidArgumentException(sprintf(
                    'Custom claim "%s" cannot replace a registered claim.',
                    $name,
                ));
            }

            $builder = $builder->withClaim($name, $value);
        }

        return $builder
            ->getToken($this->configuration->signer(), $this->configuration->signingKey())
            ->toString();
    }

    #[\Override]
    public function parse(string $token): ?Claims
    {
        try {
            $parsed = $this->configuration->parser()->parse($token);

            if (!$parsed instanceof UnencryptedToken) {
                return null;
            }

            (new SignedWith(
                $this->configuration->signer(),
                $this->configuration->verificationKey(),
            ))->assert($parsed);

            return $this->extractClaims($parsed);
        } catch (\Throwable) {
            return null;
        }
    }

    private function extractClaims(UnencryptedToken $token): ?Claims
    {
        $claims = $token->claims();
        $subject = $claims->get(RegisteredClaims::SUBJECT);
        $issuedAt = $claims->get(RegisteredClaims::ISSUED_AT);
        $expiresAt = $claims->get(RegisteredClaims::EXPIRATION_TIME);
        $issuer = $claims->get(RegisteredClaims::ISSUER);
        $audience = $claims->get(RegisteredClaims::AUDIENCE);
        $notBefore = $claims->get(RegisteredClaims::NOT_BEFORE);
        $type = $token->headers()->get('typ');

        if (
            !is_string($subject) || $subject === ''
            || !$issuedAt instanceof DateTimeImmutable
            || !$expiresAt instanceof DateTimeImmutable
            || !is_string($issuer) || $issuer === ''
            || !is_array($audience) || count($audience) !== 1
            || !is_string($audience[0] ?? null) || $audience[0] === ''
            || ($notBefore !== null && !$notBefore instanceof DateTimeImmutable)
            || !is_string($type) || $type === ''
        ) {
            return null;
        }

        $custom = [];
        foreach ($claims->all() as $name => $value) {
            if (!in_array($name, RegisteredClaims::ALL, true)) {
                $custom[$name] = $value;
            }
        }

        try {
            return new Claims(
                subject: $subject,
                issuedAt: $issuedAt->getTimestamp(),
                expiresAt: $expiresAt->getTimestamp(),
                issuer: $issuer,
                audience: $audience[0],
                type: $type,
                notBefore: $notBefore?->getTimestamp(),
                custom: $custom,
            );
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    private static function resolveKey(string $key, string $passphrase = ''): InMemory
    {
        return str_starts_with($key, 'file://')
            ? InMemory::file($key, $passphrase)
            : InMemory::plainText($key, $passphrase);
    }

    private static function resolveSigner(string $algorithm): Rsa
    {
        return match ($algorithm) {
            'RS256' => new Rsa\Sha256(),
            'RS384' => new Rsa\Sha384(),
            'RS512' => new Rsa\Sha512(),
            default => throw new \InvalidArgumentException(sprintf(
                'Unsupported RSA algorithm: %s. Supported: RS256, RS384, RS512',
                $algorithm,
            )),
        };
    }
}
