<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\DeniedReasonInterface;

/** Generic denial reason with custom code and trusted audit attributes. */
final readonly class DeniedReason implements DeniedReasonInterface, \JsonSerializable
{
    /** @param array<string, mixed> $attributes */
    public function __construct(
        public string $code,
        #[\SensitiveParameter]
        public array $attributes = [],
    ) {}

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
