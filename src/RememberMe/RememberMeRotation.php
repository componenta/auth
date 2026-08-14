<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;

/** Result of the single-winner bearer rotation phase of remember-me authentication. */
final readonly class RememberMeRotation implements \JsonSerializable
{
    public function __construct(
        public UuidInterface $subjectId,
        #[\SensitiveParameter]
        public string $previousSessionId,
        #[\SensitiveParameter]
        public string $successorToken,
        public \DateTimeImmutable $expiresAt,
    ) {
        self::assertSessionId($this->previousSessionId);

        if (preg_match('/\A[a-f0-9]{64}\z/D', $this->successorToken) !== 1) {
            throw new \InvalidArgumentException('Remember-me successor token is invalid.');
        }
    }

    /** @return array{subjectId: string, previousSessionId: string, successorToken: string, expiresAt: string} */
    public function __debugInfo(): array
    {
        return [
            'subjectId' => $this->subjectId->toString(),
            'previousSessionId' => '[REDACTED]',
            'successorToken' => '[REDACTED]',
            'expiresAt' => $this->expiresAt->format(DATE_ATOM),
        ];
    }

    /** @return array{subjectId: string, previousSessionId: string, successorToken: string, expiresAt: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    private static function assertSessionId(
        #[\SensitiveParameter]
        string $sessionId,
    ): void {
        if (
            $sessionId === ''
            || strlen($sessionId) > 512
            || preg_match('/[\x00-\x1F\x7F]/', $sessionId) === 1
        ) {
            throw new \InvalidArgumentException('Remember-me session ID is invalid.');
        }
    }
}
