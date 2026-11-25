<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Wrong password or unknown identity.
 */
final class InvalidCredentials implements DeniedReasonInterface, \JsonSerializable
{
    public string $code {
        get => 'invalid_credentials';
    }

    /** @param array<string, mixed> $attributes */
    public function __construct(
        #[\SensitiveParameter]
        public readonly array $attributes = []
    ) {
    }

    /** @return array{code: string} */
    public function __debugInfo(): array
    {
        return ['code' => $this->code];
    }

    /** @return array{code: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

}
