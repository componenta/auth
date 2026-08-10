<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

final readonly class Payload implements \JsonSerializable
{
    public function __construct(
        public string $identity,
        #[\SensitiveParameter]
        public string $password,
        public bool $remember = false,
    ) {}

    /** @return array{identity: string, password: string, remember: bool} */
    public function __debugInfo(): array
    {
        return [
            'identity' => $this->identity,
            'password' => '[REDACTED]',
            'remember' => $this->remember,
        ];
    }

    /** @return array{identity: string, password: string, remember: bool} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
