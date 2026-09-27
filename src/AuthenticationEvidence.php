<?php

declare(strict_types=1);

namespace Componenta\Auth;

/**
 * Bounded, non-secret properties established by one authentication result.
 *
 * Method and capability identifiers are intentionally extensible strings so
 * capability packages can describe their evidence without coupling auth core
 * to password, OTP, WebAuthn or another concrete mechanism.
 */
final readonly class AuthenticationEvidence implements \JsonSerializable
{
    private const int MAX_IDENTIFIERS = 16;
    private const int MAX_IDENTIFIER_LENGTH = 128;

    /** @var non-empty-list<string> */
    public array $methods;

    /** @var list<string> */
    public array $capabilities;

    /**
     * @param non-empty-list<string> $methods
     * @param list<string> $capabilities
     */
    public function __construct(
        array $methods,
        array $capabilities = [],
    ) {
        $normalizedMethods = self::normalize($methods, 'method');

        if ($normalizedMethods === []) {
            throw new \InvalidArgumentException(
                'Authentication evidence must contain at least one method.',
            );
        }

        $this->methods = $normalizedMethods;
        $this->capabilities = self::normalize($capabilities, 'capability');
    }

    public static function unknown(): self
    {
        return new self(['unknown']);
    }

    /**
     * Combines established evidence, preserving first-seen order and bounds.
     * Neither input is modified; the result still allows at most 16 identifiers
     * in each list after removing duplicates.
     */
    public function merge(self $other): self
    {
        return new self(
            methods: array_values(array_unique([
                ...$this->methods,
                ...$other->methods,
            ])),
            capabilities: array_values(array_unique([
                ...$this->capabilities,
                ...$other->capabilities,
            ])),
        );
    }

    public function hasMethod(string $method): bool
    {
        return in_array($method, $this->methods, true);
    }

    public function hasCapability(string $capability): bool
    {
        return in_array($capability, $this->capabilities, true);
    }

    /**
     * @return array{methods: non-empty-list<string>, capabilities: list<string>}
     */
    public function __debugInfo(): array
    {
        return [
            'methods' => $this->methods,
            'capabilities' => $this->capabilities,
        ];
    }

    /**
     * @return array{methods: non-empty-list<string>, capabilities: list<string>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * @param list<string> $identifiers
     * @return list<string>
     */
    private static function normalize(array $identifiers, string $label): array
    {
        if (count($identifiers) > self::MAX_IDENTIFIERS) {
            throw new \InvalidArgumentException(sprintf(
                'Authentication evidence may contain at most %d %s identifiers.',
                self::MAX_IDENTIFIERS,
                $label,
            ));
        }

        $normalized = [];

        foreach ($identifiers as $identifier) {
            if (
                $identifier === ''
                || strlen($identifier) > self::MAX_IDENTIFIER_LENGTH
                || preg_match('/\A[a-z0-9][a-z0-9._:-]*\z/D', $identifier) !== 1
            ) {
                throw new \InvalidArgumentException(sprintf(
                    'Authentication evidence %s identifier "%s" is invalid.',
                    $label,
                    $identifier,
                ));
            }

            $normalized[$identifier] = $identifier;
        }

        return array_values($normalized);
    }
}
