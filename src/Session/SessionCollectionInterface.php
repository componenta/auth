<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Arrayable\Arrayable;

/**
 * Collection of sessions with filtering capabilities.
 *
 * @extends \IteratorAggregate<int, SessionInterface>
 */
interface SessionCollectionInterface extends Arrayable, \IteratorAggregate, \Countable
{
    /**
     * Finds session(s) by ID.
     *
     * If string is passed, returns single session or null if not found.
     * If array is passed, always returns collection (may be empty).
     *
     * @param string|string[] $id
     * @return ($id is string ? ?SessionInterface : SessionCollectionInterface)
     */
    public function find(string|array $id): SessionInterface|SessionCollectionInterface|null;

    /**
     * Filters sessions by callback.
     *
     * @param callable(SessionInterface): bool $callback
     */
    public function filter(callable $callback): SessionCollectionInterface;

    /**
     * Extracts values from sessions into array.
     *
     * @param string $key Property name or attribute key
     * @return array<mixed>
     */
    public function pluck(string $key = 'id'): array;

    /**
     * Checks if collection is empty.
     */
    public function isEmpty(): bool;
}