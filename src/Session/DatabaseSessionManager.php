<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Event\SessionsTerminated;
use Componenta\Clock\DateTimeFactoryInterface;
use Cycle\Database\DatabaseInterface;

final readonly class DatabaseSessionManager implements SessionManagerInterface
{
    public const string ATTR_IP = 'ip';
    public const string ATTR_USER_AGENT = 'user_agent';
    private const int MAX_CHAIN_DEPTH = 10;

    public function __construct(
        private DatabaseInterface $database,
        private SessionIdGeneratorInterface $idGenerator,
        private DateTimeFactoryInterface $dateTimeFactory,
        private EventDispatcher $dispatcher,
        private DatabaseSessionManagerConfig $config = new DatabaseSessionManagerConfig(),
    ) {}

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
        $this->insert($session, $ip, $userAgent);
        return $session;
    }

    public function exists(string $sessionId): bool
    {
        return $this->database->select('1')->from($this->config->table)
            ->where($this->config->idColumn, $sessionId)->run()->fetch() !== false;
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
        $row = $this->database->select()->from($this->config->table)
            ->where($this->config->idColumn, $sessionId)->run()->fetch();
        if ($row === false) {
            return null;
        }
        $session = $this->hydrate($row);
        $now = $this->dateTimeFactory->now();
        if ($session->replacedBy !== null) {
            return $session->expiresAt <= $now
                ? null
                : $this->findWithDepth($session->replacedBy, $depth + 1);
        }
        if ($session->absoluteExpiresAt <= $now || $session->expiresAt <= $now) {
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

    public function touch(string $sessionId, ?\DateTimeImmutable $lastActiveAt = null): void
    {
        $now = $this->dateTimeFactory->now();
        $touchBefore = $now->modify("-{$this->config->touchInterval} seconds");
        if ($lastActiveAt !== null && $lastActiveAt > $touchBefore) {
            return;
        }

        $query = $this->database->update($this->config->table)
            ->where($this->config->idColumn, $sessionId)
            ->where($this->config->replacedByColumn, null);
        if ($this->config->touchInterval > 0) {
            $query->where($this->config->lastActiveAtColumn, '<=', $touchBefore->format($this->config->dateFormat));
        }
        $query->values([
            $this->config->lastActiveAtColumn => $now->format($this->config->dateFormat),
            $this->config->expiresAtColumn => $now->modify("+{$this->config->idleTimeout} seconds")->format($this->config->dateFormat),
        ])->run();
    }

    public function terminate(string|iterable|SessionCollectionInterface $sessionId): void
    {
        $ids = $this->normalizeIds($sessionId);
        if ($ids === []) {
            return;
        }
        $this->database->transaction(function () use ($ids): void {
            $this->database->delete($this->config->table)
                ->where($this->config->idColumn, 'IN', $ids)->run();
            $this->dispatcher->dispatch(new SessionsTerminated($ids));
        });
    }

    public function terminateAll(int|string $userId, ?string $exceptSessionId = null): void
    {
        $this->database->transaction(function () use ($userId, $exceptSessionId): void {
            $query = $this->database->delete($this->config->table)
                ->where($this->config->userIdColumn, $userId);
            if ($exceptSessionId !== null) {
                $query->where($this->config->idColumn, '!=', $exceptSessionId);
            }
            $query->run();
            $this->dispatcher->dispatch(new AllSessionsTerminated($userId, $exceptSessionId));
        });
    }

    public function cleanup(int $limit = 1000): int
    {
        if ($limit < 1) {
            throw new \InvalidArgumentException('Session cleanup limit must be greater than zero.');
        }
        $now = $this->dateTimeFactory->now()->format($this->config->dateFormat);
        $rows = $this->database->select($this->config->idColumn)
            ->from($this->config->table)
            ->where(function ($query) use ($now): void {
                $query->where($this->config->expiresAtColumn, '<', $now)
                    ->orWhere($this->config->absoluteExpiresAtColumn, '<', $now);
            })
            ->limit($limit)
            ->run()
            ->fetchAll();
        $ids = array_map(
            fn(array $row): string => (string) $row[$this->config->idColumn],
            $rows,
        );
        if ($ids === []) {
            return 0;
        }
        return $this->database->delete($this->config->table)
            ->where($this->config->idColumn, 'IN', $ids)->run();
    }

    public function regenerate(string $sessionId): SessionInterface
    {
        $row = $this->database->select()->from($this->config->table)
            ->where($this->config->idColumn, $sessionId)->run()->fetch();
        if ($row === false) {
            throw new \InvalidArgumentException('Session not found');
        }
        $old = $this->hydrate($row);
        $now = $this->dateTimeFactory->now();
        if ($old->replacedBy !== null) {
            return $this->find($old->replacedBy) ?? throw new \InvalidArgumentException('Session not found');
        }
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
        try {
            $this->database->transaction(function () use ($sessionId, $new, $now): void {
                $this->insert(
                    $new,
                    (string) $new->getAttribute(self::ATTR_IP, ''),
                    (string) $new->getAttribute(self::ATTR_USER_AGENT, ''),
                );
                $affectedRows = $this->database->update($this->config->table)
                    ->where($this->config->idColumn, $sessionId)
                    ->where($this->config->replacedByColumn, null)
                    ->values([
                        $this->config->replacedByColumn => $new->id,
                        $this->config->expiresAtColumn => $now->modify("+{$this->config->regenerationGracePeriod} seconds")->format($this->config->dateFormat),
                    ])->run();
                if ($affectedRows === 0) {
                    throw new ConcurrentRegenerationException();
                }
                $this->dispatcher->dispatch(new SessionRegenerated($sessionId, $new->id));
            });
        } catch (ConcurrentRegenerationException) {
            return $this->find($sessionId) ?? throw new \InvalidArgumentException('Session not found');
        }
        return $new;
    }

    private function insert(SessionInterface $session, string $ip, string $userAgent): void
    {
        $this->database->insert($this->config->table)->values([
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
        ])->run();
    }

    /** @return string[] */
    private function normalizeIds(string|iterable|SessionCollectionInterface $sessionId): array
    {
        if (is_string($sessionId)) {
            return [$sessionId];
        }
        $ids = $sessionId instanceof SessionCollectionInterface ? $sessionId->pluck() : [...$sessionId];
        return array_values(array_unique($ids));
    }

    /** @return SessionInterface[] */
    private function fetchAll(int|string $userId): array
    {
        $now = $this->dateTimeFactory->now();
        $rows = $this->database->select()->from($this->config->table)
            ->where($this->config->userIdColumn, $userId)
            ->where($this->config->replacedByColumn, null)
            ->where($this->config->absoluteExpiresAtColumn, '>', $now->format($this->config->dateFormat))
            ->where($this->config->expiresAtColumn, '>', $now->format($this->config->dateFormat))
            ->orderBy($this->config->lastActiveAtColumn, 'DESC')->run()->fetchAll();
        return array_map($this->hydrate(...), $rows);
    }

    /** @param array<string, mixed> $row */
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
