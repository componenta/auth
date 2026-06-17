<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Event\SessionsTerminated;
use Componenta\Clock\DateTimeFactoryInterface;
use Cycle\Database\DatabaseInterface;

final readonly class DatabaseSessionManager implements SessionManagerInterface
{
    /** Attribute key for client IP address. */
    public const string ATTR_IP = 'ip';

    /** Attribute key for client User-Agent string. */
    public const string ATTR_USER_AGENT = 'user_agent';

    /** Maximum depth for following replacement chains in find(). */
    private const int MAX_CHAIN_DEPTH = 10;

    public function __construct(
        private DatabaseInterface $database,
        private SessionIdGeneratorInterface $idGenerator,
        private DateTimeFactoryInterface $dateTimeFactory,
        private EventDispatcher $dispatcher,
        private DatabaseSessionManagerConfig $config = new DatabaseSessionManagerConfig(),
    ) {}

    /**
     * @throws \InvalidArgumentException If required attributes (ip, user_agent) are missing
     * @throws \JsonException
     */
    public function create(int|string $userId, array $attributes = []): SessionInterface
    {
        $ip = $attributes[self::ATTR_IP] ?? throw new \InvalidArgumentException('Missing required attribute: ' . self::ATTR_IP);
        $userAgent = $attributes[self::ATTR_USER_AGENT] ?? throw new \InvalidArgumentException('Missing required attribute: ' . self::ATTR_USER_AGENT);

        $now = $this->dateTimeFactory->now();

        $session = new Session(
            id: $this->idGenerator->generate(),
            userId: $userId,
            expiresAt: $now->modify("+{$this->config->idleTimeout} seconds"),
            absoluteExpiresAt: $now->modify("+{$this->config->absoluteTimeout} seconds"),
            regenerateAt: $now->modify("+{$this->config->regenerationInterval} seconds"),
            replacedBy: null,
            createdAt: $now,
            lastActiveAt: $now,
            attributes: $attributes,
        );

        $this->database
            ->insert($this->config->table)
            ->values([
                $this->config->idColumn => $session->id,
                $this->config->userIdColumn => $session->userId,
                $this->config->ipColumn => $ip,
                $this->config->userAgentColumn => $userAgent,
                $this->config->expiresAtColumn => $session->expiresAt->format($this->config->dateFormat),
                $this->config->absoluteExpiresAtColumn => $session->absoluteExpiresAt->format($this->config->dateFormat),
                $this->config->regenerateAtColumn => $session->regenerateAt->format($this->config->dateFormat),
                $this->config->replacedByColumn => null,
                $this->config->createdAtColumn => $session->createdAt->format($this->config->dateFormat),
                $this->config->lastActiveAtColumn => $session->lastActiveAt->format($this->config->dateFormat),
                $this->config->attributesColumn => json_encode($session->getAttributes(), JSON_THROW_ON_ERROR),
            ])
            ->run();

        return $session;
    }

    public function exists(string $sessionId): bool
    {
        return $this->database
                ->select('1')
                ->from($this->config->table)
                ->where($this->config->idColumn, $sessionId)
                ->run()
                ->fetch() !== false;
    }

    public function find(string $sessionId): ?SessionInterface
    {
        return $this->findWithDepth($sessionId, 0);
    }

    private function findWithDepth(string $sessionId, int $depth): ?SessionInterface
    {
        if ($depth > self::MAX_CHAIN_DEPTH) {
            return null;
        }

        $row = $this->database
            ->select()
            ->from($this->config->table)
            ->where($this->config->idColumn, $sessionId)
            ->run()
            ->fetch();

        if ($row === false) {
            return null;
        }

        $session = $this->hydrate($row);
        $now = $this->dateTimeFactory->now();

        // Replaced session: follow to replacement if grace period not expired
        if ($session->replacedBy !== null) {
            if ($session->expiresAt <= $now) {
                return null;
            }

            return $this->findWithDepth($session->replacedBy, $depth + 1);
        }

        // Absolute timeout: non-negotiable expiration
        if ($session->absoluteExpiresAt <= $now) {
            return null;
        }

        // Idle timeout
        if ($session->expiresAt <= $now) {
            return null;
        }

        return $session;
    }

    public function all(int|string $userId): SessionCollectionInterface
    {
        if ($this->config->lazyLoad) {
            $reflector = new \ReflectionClass(SessionCollection::class);

            return $reflector->newLazyGhost(function (SessionCollection $ghost) use ($userId): void {
                $ghost->__construct($this->fetchAll($userId));
            });
        }

        return new SessionCollection($this->fetchAll($userId));
    }

    public function touch(string $sessionId): void
    {
        $now = $this->dateTimeFactory->now();

        $this->database
            ->update($this->config->table)
            ->where($this->config->idColumn, $sessionId)
            ->where($this->config->replacedByColumn, null)
            ->values([
                $this->config->lastActiveAtColumn => $now->format($this->config->dateFormat),
                $this->config->expiresAtColumn => $now->modify("+{$this->config->idleTimeout} seconds")->format($this->config->dateFormat),
            ])
            ->run();
    }

    public function terminate(string|iterable|SessionCollectionInterface $sessionId): void
    {
        $ids = $this->normalizeIds($sessionId);

        if ($ids === []) {
            return;
        }

        $this->database
            ->delete($this->config->table)
            ->where($this->config->idColumn, 'IN', $ids)
            ->run();

        $this->dispatch(new SessionsTerminated($ids));
    }

    public function terminateAll(int|string $userId, ?string $exceptSessionId = null): void
    {
        $query = $this->database
            ->delete($this->config->table)
            ->where($this->config->userIdColumn, $userId);

        if ($exceptSessionId !== null) {
            $query->where($this->config->idColumn, '!=', $exceptSessionId);
        }

        $query->run();

        $this->dispatch(new AllSessionsTerminated($userId, $exceptSessionId));
    }

    public function cleanup(): void
    {
        $now = $this->dateTimeFactory->now()->format($this->config->dateFormat);

        $this->database
            ->delete($this->config->table)
            ->where(function ($query) use ($now): void {
                $query
                    ->orWhere($this->config->expiresAtColumn, '<', $now)
                    ->orWhere($this->config->absoluteExpiresAtColumn, '<', $now);
            })
            ->run();
    }

    public function regenerate(string $sessionId): SessionInterface
    {
        $row = $this->database
            ->select()
            ->from($this->config->table)
            ->where($this->config->idColumn, $sessionId)
            ->run()
            ->fetch();

        if ($row === false) {
            throw new \InvalidArgumentException('Session not found');
        }

        $old = $this->hydrate($row);
        $now = $this->dateTimeFactory->now();

        // Already replaced by a concurrent request - follow the chain
        if ($old->replacedBy !== null) {
            return $this->find($old->replacedBy)
                ?? throw new \InvalidArgumentException('Session not found');
        }

        // Check timeouts
        if ($old->absoluteExpiresAt <= $now || $old->expiresAt <= $now) {
            throw new \InvalidArgumentException('Session expired');
        }

        $new = new Session(
            id: $this->idGenerator->generate(),
            userId: $old->userId,
            expiresAt: $now->modify("+{$this->config->idleTimeout} seconds"),
            absoluteExpiresAt: $old->absoluteExpiresAt,
            regenerateAt: $now->modify("+{$this->config->regenerationInterval} seconds"),
            replacedBy: null,
            createdAt: $now,
            lastActiveAt: $now,
            attributes: $old->getAttributes(),
        );

        // INSERT new + claim old with optimistic lock, atomically.
        // If the claim UPDATE affects 0 rows (a concurrent request already
        // regenerated this session), throwing triggers a rollback so the
        // just-inserted new row is undone - no orphan can leak. INSERT
        // must come first to satisfy a potential FK (replaced_by -> id).
        try {
            $this->database->transaction(function () use ($sessionId, $new, $now): void {
                $this->database
                    ->insert($this->config->table)
                    ->values([
                        $this->config->idColumn => $new->id,
                        $this->config->userIdColumn => $new->userId,
                        $this->config->ipColumn => $new->getAttribute(self::ATTR_IP, ''),
                        $this->config->userAgentColumn => $new->getAttribute(self::ATTR_USER_AGENT, ''),
                        $this->config->expiresAtColumn => $new->expiresAt->format($this->config->dateFormat),
                        $this->config->absoluteExpiresAtColumn => $new->absoluteExpiresAt->format($this->config->dateFormat),
                        $this->config->regenerateAtColumn => $new->regenerateAt->format($this->config->dateFormat),
                        $this->config->replacedByColumn => null,
                        $this->config->createdAtColumn => $new->createdAt->format($this->config->dateFormat),
                        $this->config->lastActiveAtColumn => $new->lastActiveAt->format($this->config->dateFormat),
                        $this->config->attributesColumn => json_encode($new->getAttributes(), JSON_THROW_ON_ERROR),
                    ])
                    ->run();

                $affectedRows = $this->database
                    ->update($this->config->table)
                    ->where($this->config->idColumn, $sessionId)
                    ->where($this->config->replacedByColumn, null)
                    ->values([
                        $this->config->replacedByColumn => $new->id,
                        $this->config->expiresAtColumn => $now->modify("+{$this->config->regenerationGracePeriod} seconds")->format($this->config->dateFormat),
                    ])
                    ->run();

                if ($affectedRows === 0) {
                    throw new ConcurrentRegenerationException();
                }
            });
        } catch (ConcurrentRegenerationException) {
            return $this->find($sessionId)
                ?? throw new \InvalidArgumentException('Session not found');
        }

        $this->dispatch(new SessionRegenerated($sessionId, $new->id));

        return $new;
    }

    private function dispatch(EventInterface $event): void
    {
        $this->dispatcher->dispatch($event);
    }

    /**
     * @return string[]
     */
    private function normalizeIds(string|iterable|SessionCollectionInterface $sessionId): array
    {
        if (is_string($sessionId)) {
            return [$sessionId];
        }

        if ($sessionId instanceof SessionCollectionInterface) {
            return $sessionId->pluck();
        }

        return [...$sessionId];
    }

    /**
     * @return SessionInterface[]
     */
    private function fetchAll(int|string $userId): array
    {
        $now = $this->dateTimeFactory->now();

        $rows = $this->database
            ->select()
            ->from($this->config->table)
            ->where($this->config->userIdColumn, $userId)
            ->where($this->config->replacedByColumn, null)
            ->where($this->config->absoluteExpiresAtColumn, '>', $now->format($this->config->dateFormat))
            ->where($this->config->expiresAtColumn, '>', $now->format($this->config->dateFormat))
            ->orderBy($this->config->lastActiveAtColumn, 'DESC')
            ->run()
            ->fetchAll();

        return array_map($this->hydrate(...), $rows);
    }

    /**
     * @param array<string, mixed> $row
     * @throws \JsonException
     */
    private function hydrate(array $row): SessionInterface
    {
        return new Session(
            id: $row[$this->config->idColumn],
            userId: $row[$this->config->userIdColumn],
            expiresAt: $this->dateTimeFactory->parse($row[$this->config->expiresAtColumn]),
            absoluteExpiresAt: $this->dateTimeFactory->parse($row[$this->config->absoluteExpiresAtColumn]),
            regenerateAt: $this->dateTimeFactory->parse($row[$this->config->regenerateAtColumn]),
            replacedBy: $row[$this->config->replacedByColumn],
            createdAt: $this->dateTimeFactory->parse($row[$this->config->createdAtColumn]),
            lastActiveAt: $this->dateTimeFactory->parse($row[$this->config->lastActiveAtColumn]),
            attributes: json_decode($row[$this->config->attributesColumn], true, 512, JSON_THROW_ON_ERROR),
        );
    }
}
