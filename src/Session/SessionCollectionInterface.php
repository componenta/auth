<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Arrayable\Arrayable;

/** @extends \IteratorAggregate<int, SessionInterface> */
interface SessionCollectionInterface extends Arrayable, \IteratorAggregate, \Countable
{
    public bool $empty { get; }

    /**
     * @param string|string[] $id
     * @return ($id is string ? ?SessionInterface : SessionCollectionInterface)
     */
    public function find(
        #[\SensitiveParameter]
        string|array $id,
    ): SessionInterface|SessionCollectionInterface|null;

    /** @param callable(SessionInterface): bool $callback */
    public function filter(
        #[\SensitiveParameter]
        callable $callback,
    ): SessionCollectionInterface;

    /** @return array<mixed> */
    public function pluck(string $key = 'id'): array;
}
