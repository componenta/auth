<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

/**
 * Password authentication payload.
 *
 * Carries credentials from the extractor to the strategy. The password
 * is masked in every serialization path (var_dump, json_encode, stack
 * traces) so that listeners, loggers, or error trackers cannot leak
 * it accidentally when they capture authentication events.
 */
final readonly class Payload implements RememberMeAwareInterface, \JsonSerializable
{
    public function __construct(
        public string $identity,
        #[\SensitiveParameter]
        public string $password,
        public bool $remember = false,
    ) {}

    /**
     * @return array{identity: string, password: string, remember: bool}
     */
    public function __debugInfo(): array
    {
        return [
            'identity' => $this->identity,
            'password' => '[REDACTED]',
            'remember' => $this->remember,
        ];
    }

    /**
     * @return array{identity: string, password: string, remember: bool}
     */
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
