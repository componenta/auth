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
    public function __construct(iterable $sessions = [])
    {
        $indexed = [];

        foreach ($sessions as $session) {
            $indexed[$session->id] = $session;
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
    public function find(string|array $id): SessionInterface|self|null
    {
        if (is_string($id)) {
            return $this->sessions[$id] ?? null;
        }

        return new self(array_intersect_key($this->sessions, array_flip($id)));
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
}
