<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

final readonly class SessionCollection implements SessionCollectionInterface, \JsonSerializable
{
    private const array PROPERTIES = [
        'id', 'subjectId', 'expiresAt', 'absoluteExpiresAt', 'regenerateAt',
        'replacedBy', 'createdAt', 'lastActiveAt', 'attributes',
    ];

    /** @var array<string, SessionInterface> */
    private array $sessions;

    public bool $empty;

    /** @param iterable<SessionInterface> $sessions */
    public function __construct(
        #[\SensitiveParameter]
        iterable $sessions = [],
    ) {
        $indexed = [];

        foreach ($sessions as $session) {
            $indexed[self::idKey($session->id)] = $session;
        }

        $this->sessions = $indexed;
        $this->empty = $indexed === [];
    }

    /** @return array{count: int, empty: bool} */
    public function __debugInfo(): array
    {
        return [
            'count' => count($this->sessions),
            'empty' => $this->empty,
        ];
    }

    /** @return array{count: int, empty: bool} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    #[\Override]
    public function find(
        #[\SensitiveParameter]
        string|array $id,
    ): SessionInterface|self|null {
        if (is_string($id)) {
            return $this->sessions[self::idKey($id)] ?? null;
        }

        $found = [];
        foreach ($id as $sessionId) {
            if (!is_string($sessionId)) {
                throw new \InvalidArgumentException('Every session ID must be a string.');
            }

            $key = self::idKey($sessionId);
            if (isset($this->sessions[$key])) {
                $found[] = $this->sessions[$key];
            }
        }

        return new self($found);
    }

    #[\Override]
    public function filter(callable $callback): static
    {
        return new self(array_filter($this->sessions, $callback));
    }

    #[\Override]
    public function pluck(string $key = 'id'): array
    {
        return array_map(
            static function (SessionInterface $session) use ($key): mixed {
                if (in_array($key, self::PROPERTIES, true)) {
                    return $session->{$key};
                }

                if ($session->hasAttribute($key)) {
                    return $session->getAttribute($key);
                }

                throw new \OutOfBoundsException(sprintf(
                    'Session property or attribute "%s" does not exist.',
                    $key,
                ));
            },
            array_values($this->sessions),
        );
    }

    /** @return list<SessionInterface> */
    #[\Override]
    public function toArray(): array
    {
        return array_values($this->sessions);
    }

    #[\Override]
    public function count(): int
    {
        return count($this->sessions);
    }

    #[\Override]
    public function getIterator(): \Traversable
    {
        yield from $this->toArray();
    }

    private static function idKey(
        #[\SensitiveParameter]
        string $id,
    ): string {
        return 's:' . $id;
    }
}
