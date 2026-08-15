<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;

/** Signals that a superseded remember-me bearer was replayed. */
final readonly class RememberMeCompromise implements \JsonSerializable
{
    /** @var non-empty-list<string> */
    public array $sessionIds;

    /** @param non-empty-list<string> $sessionIds */
    public function __construct(
        public UuidInterface $subjectId,
        #[\SensitiveParameter]
        array $sessionIds,
    ) {
        /** @var array<string, string> $unique */
        $unique = [];

        foreach ($sessionIds as $sessionId) {
            if (
                !is_string($sessionId)
                || $sessionId === ''
                || strlen($sessionId) > 512
                || preg_match('/[\x00-\x1F\x7F]/', $sessionId) === 1
            ) {
                throw new \InvalidArgumentException(
                    'Remember-me compromise session ID is invalid.',
                );
            }

            $unique['s:' . $sessionId] = $sessionId;
        }

        if ($unique === []) {
            throw new \InvalidArgumentException(
                'Remember-me compromise must identify at least one session.',
            );
        }

        $this->sessionIds = array_values($unique);
    }

    /** @return array{subjectId: string, sessionIds: string} */
    public function __debugInfo(): array
    {
        return [
            'subjectId' => $this->subjectId->toString(),
            'sessionIds' => '[REDACTED]',
        ];
    }

    /** @return array{subjectId: string, sessionIds: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}