<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * Default implementation of SessionCollectionInterface.
 */
final readonly class SessionCollection implements SessionCollectionInterface
{
    /** @var array<string, SessionInterface> */
    private array $sessions;

    /**
     * @param iterable<SessionInterface> $sessions
     */
    public function __construct(iterable $sessions = [])
    {
        $indexed = [];

        foreach ($sessions as $session) {
            $indexed[$session->id] = $session;
        }

        $this->sessions = $indexed;
    }

    public function find(string|array $id): SessionInterface|self|null
    {
        if (is_string($id)) {
            return $this->sessions[$id] ?? null;
        }

        return new self(array_intersect_key($this->sessions, array_flip($id)));
    }

    public function filter(callable $callback): static
    {
        return new self(array_filter($this->sessions, $callback));
    }

    public function pluck(string $key = 'id'): array
    {
        return array_map(
            static fn(SessionInterface $session) => $session->$key,
            array_values($this->sessions),
        );
    }

    public function toArray(): array
    {
        return array_values($this->sessions);
    }

    public function isEmpty(): bool
    {
        return $this->sessions === [];
    }

    public function count(): int
    {
        return count($this->sessions);
    }

    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->toArray());
    }
}
