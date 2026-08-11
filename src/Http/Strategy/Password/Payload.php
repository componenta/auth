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
    ) {
        if (
            $this->identity === ''
            || strlen($this->identity) > 320
            || preg_match('/[\x00-\x1F\x7F]/', $this->identity) === 1
        ) {
            throw new \InvalidArgumentException('Password identity is invalid.');
        }

        if ($this->password === '' || strlen($this->password) > 4096) {
            throw new \InvalidArgumentException('Password credential is invalid.');
        }
    }

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
