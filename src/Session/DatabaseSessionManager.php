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
    private const int MAX_SESSION_ID_LENGTH = 512;
    private const int MAX_USER_ID_LENGTH = 512;
    private const int MAX_IP_LENGTH = 45;
    private const int MAX_USER_AGENT_LENGTH = 1024;
    private const int DELETE_CHUNK_SIZE = 500;
    private const int MAX_CLEANUP_LIMIT = 10000;

    public function __construct(
        private DatabaseInterface $database,
        private SessionIdGeneratorInterface $idGenerator,
        private DateTimeFactoryInterface $dateTimeFactory,
        private EventDispatcher $dispatcher,
        private DatabaseSessionManagerConfig $config = new DatabaseSessionManagerConfig(),
    ) {}

    #[\Override]
    public function create(int|string $userId, array $attributes = []): SessionInterface
    {
        $ip = $attributes[self::ATTR_IP]
            ?? throw new \InvalidArgumentException('Missing required attribute: ' . self::ATTR_IP);
        $userAgent = $attributes[self::ATTR_USER_AGENT]
            ?? throw new \InvalidArgumentException(
                'Missing required attribute: ' . self::ATTR_USER_AGENT,
            );

        if (!is_string($ip) || strlen($ip) > self::MAX_IP_LENGTH) {
            throw new \InvalidArgumentException(
                'Session IP attribute must be a bounded string.',
            );
        }

        if (
            !is_string($userAgent)
            || strlen($userAgent) > self::MAX_USER_AGENT_LENGTH
        ) {
            throw new \InvalidArgumentException(
                'Session User-Agent attribute must be a bounded string.',
            );
        }

        self::assertUserId($userId);

        $sessionId = $this->idGenerator->generate();
        self::assertSessionId($sessionId);
        $now = $this->dateTimeFactory->now();

        $session = new Session(
            id: $sessionId,
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

    #[\Override]
    public function exists(string $sessionId): bool
    {
        self::assertSessionId($sessionId);

        return $this->database
            ->select('1')
            ->from($this->config->table)
            ->where($this->config->idColumn, $sessionId)
            ->run()
            ->fetch() !== false;
    }

    #[\Override]
    public function find(string $sessionId): ?SessionInterface
    {
        self::assertSessionId($sessionId);

        return $this->findWithDepth($sessionId, 0);
    }

    private function findWithDepth(string $sessionId, int $depth): ?SessionInterface
    {
        if ($depth > self::MAX_CHAIN_DEPTH) {
            return null;
        }

        self::assertSessionId($sessionId);

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

    #[\Override]
    public function all(int|string $userId): SessionCollectionInterface
    {
        self::assertUserId($userId);

        if ($this->config->lazyLoad) {
            $reflector = new \ReflectionClass(SessionCollection::class);

            return $reflector->newLazyGhost(
                function (SessionCollection $ghost) use ($userId): void {
                    $ghost->__construct($this->fetchAll($userId));
                },
            );
        }

        return new SessionCollection($this->fetchAll($userId));
    }

    #[\Override]
    public function touch(string $sessionId, ?\DateTimeImmutable $lastActiveAt = null): void
    {
        self::assertSessionId($sessionId);
        $now = $this->dateTimeFactory->now();
        $formattedNow = $now->format($this->config->dateFormat);
        $touchBefore = $now->modify("-{$this->config->touchInterval} seconds");

        if ($lastActiveAt !== null && $lastActiveAt > $touchBefore) {
            return;
        }

        $query = $this->database
            ->update($this->config->table)
            ->where($this->config->idColumn, $sessionId)
            ->where($this->config->replacedByColumn, null)
            ->where($this->config->expiresAtColumn, '>', $formattedNow)
            ->where($this->config->absoluteExpiresAtColumn, '>', $formattedNow);

        if ($this->config->touchInterval > 0) {
            $query->where(
                $this->config->lastActiveAtColumn,
                '<=',
                $touchBefore->format($this->config->dateFormat),
            );
        }

        $query
            ->values([
                $this->config->lastActiveAtColumn => $now->format($this->config->dateFormat),
                $this->config->expiresAtColumn => $now
                    ->modify("+{$this->config->idleTimeout} seconds")
                    ->format($this->config->dateFormat),
            ])
            ->run();
    }

    #[\Override]
    public function terminate(string|iterable|SessionCollectionInterface $sessionId): void
    {
        $ids = $this->normalizeIds($sessionId);

        if ($ids === []) {
            return;
        }

        $this->database->transaction(function () use ($ids): void {
            foreach (array_chunk($ids, self::DELETE_CHUNK_SIZE) as $chunk) {
                $this->database
                    ->delete($this->config->table)
                    ->where($this->config->idColumn, 'IN', $chunk)
                    ->run();
            }

            $this->dispatcher->dispatch(new SessionsTerminated($ids));
        });
    }

    #[\Override]
    public function terminateAll(int|string $userId, ?string $exceptSessionId = null): void
    {
        self::assertUserId($userId);

        if ($exceptSessionId !== null) {
            self::assertSessionId($exceptSessionId);
        }

        $this->database->transaction(function () use ($userId, $exceptSessionId): void {
            $query = $this->database
                ->delete($this->config->table)
                ->where($this->config->userIdColumn, $userId);

            if ($exceptSessionId !== null) {
                $query->where($this->config->idColumn, '!=', $exceptSessionId);
            }

            $query->run();
            $this->dispatcher->dispatch(
                new AllSessionsTerminated($userId, $exceptSessionId),
            );
        });
    }

    #[\Override]
    public function cleanup(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > self::MAX_CLEANUP_LIMIT) {
            throw new \InvalidArgumentException(sprintf(
                'Session cleanup limit must be between 1 and %d.',
                self::MAX_CLEANUP_LIMIT,
            ));
        }

        $now = $this->dateTimeFactory->now()->format($this->config->dateFormat);
        $rows = $this->database
            ->select($this->config->idColumn)
            ->from($this->config->table)
            ->where(function ($query) use ($now): void {
                $query
                    ->where($this->config->expiresAtColumn, '<=', $now)
                    ->orWhere($this->config->absoluteExpiresAtColumn, '<=', $now);
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

        $deleted = 0;

        foreach (array_chunk($ids, self::DELETE_CHUNK_SIZE) as $chunk) {
            $deleted += $this->database
                ->delete($this->config->table)
                ->where($this->config->idColumn, 'IN', $chunk)
                ->where(function ($query) use ($now): void {
                    $query
                        ->where($this->config->expiresAtColumn, '<=', $now)
                        ->orWhere(
                            $this->config->absoluteExpiresAtColumn,
                            '<=',
                            $now,
                        );
                })
                ->run();
        }

        return $deleted;
    }

    #[\Override]
    public function regenerate(string $sessionId): SessionInterface
    {
        self::assertSessionId($sessionId);

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

        if ($old->replacedBy !== null) {
            return $this->find($old->replacedBy)
                ?? throw new \InvalidArgumentException('Session not found');
        }

        if ($old->absoluteExpiresAt <= $now || $old->expiresAt <= $now) {
            throw new \InvalidArgumentException('Session expired');
        }

        $newSessionId = $this->idGenerator->generate();
        self::assertSessionId($newSessionId);

        $new = new Session(
            id: $newSessionId,
            userId: $old->userId,
            expiresAt: $now->modify("+{$this->config->idleTimeout} seconds"),
            absoluteExpiresAt: $old->absoluteExpiresAt,
            regenerateAt: $now->modify("+{$this->config->regenerationInterval} seconds"),
            replacedBy: null,
            createdAt: $now,
            lastActiveAt: $now,
            attributes: $old->attributes,
        );

        try {
            $this->database->transaction(function () use ($sessionId, $new, $now): void {
                $this->insert(
                    $new,
                    (string) $new->getAttribute(self::ATTR_IP, ''),
                    (string) $new->getAttribute(self::ATTR_USER_AGENT, ''),
                );

                $affectedRows = $this->database
                    ->update($this->config->table)
                    ->where($this->config->idColumn, $sessionId)
                    ->where($this->config->replacedByColumn, null)
                    ->values([
                        $this->config->replacedByColumn => $new->id,
                        $this->config->expiresAtColumn => $now
                            ->modify("+{$this->config->regenerationGracePeriod} seconds")
                            ->format($this->config->dateFormat),
                    ])
                    ->run();

                if ($affectedRows === 0) {
                    throw new ConcurrentRegenerationException();
                }

                $this->dispatcher->dispatch(new SessionRegenerated($sessionId, $new->id));
            });
        } catch (ConcurrentRegenerationException) {
            return $this->find($sessionId)
                ?? throw new \InvalidArgumentException('Session not found');
        }

        return $new;
    }

    private function insert(SessionInterface $session, string $ip, string $userAgent): void
    {
        $this->database
            ->insert($this->config->table)
            ->values([
                $this->config->idColumn => $session->id,
                $this->config->userIdColumn => $session->userId,
                $this->config->ipColumn => $ip,
                $this->config->userAgentColumn => $userAgent,
                $this->config->expiresAtColumn => $session->expiresAt
                    ->format($this->config->dateFormat),
                $this->config->absoluteExpiresAtColumn => $session->absoluteExpiresAt
                    ->format($this->config->dateFormat),
                $this->config->regenerateAtColumn => $session->regenerateAt
                    ->format($this->config->dateFormat),
                $this->config->replacedByColumn => null,
                $this->config->createdAtColumn => $session->createdAt
                    ->format($this->config->dateFormat),
                $this->config->lastActiveAtColumn => $session->lastActiveAt
                    ->format($this->config->dateFormat),
                $this->config->attributesColumn => json_encode(
                    $session->attributes,
                    JSON_THROW_ON_ERROR,
                ),
            ])
            ->run();
    }

    /** @return string[] */
    private function normalizeIds(
        string|iterable|SessionCollectionInterface $sessionId,
    ): array {
        if (is_string($sessionId)) {
            self::assertSessionId($sessionId);

            return [$sessionId];
        }

        $source = $sessionId instanceof SessionCollectionInterface
            ? $sessionId->pluck()
            : $sessionId;
        $ids = [];

        foreach ($source as $id) {
            if (!is_string($id)) {
                throw new \InvalidArgumentException(
                    'Every session ID must be a string.',
                );
            }

            self::assertSessionId($id);
            $ids[$id] = true;
        }

        return array_keys($ids);
    }

    private static function assertUserId(int|string $userId): void
    {
        if (is_string($userId) && (
            $userId === ''
            || strlen($userId) > self::MAX_USER_ID_LENGTH
        )) {
            throw new \InvalidArgumentException(sprintf(
                'Session user ID must contain between 1 and %d bytes.',
                self::MAX_USER_ID_LENGTH,
            ));
        }
    }

    private static function assertSessionId(string $sessionId): void
    {
        if (
            $sessionId === ''
            || strlen($sessionId) > self::MAX_SESSION_ID_LENGTH
        ) {
            throw new \InvalidArgumentException(sprintf(
                'Session ID must contain between 1 and %d bytes.',
                self::MAX_SESSION_ID_LENGTH,
            ));
        }
    }

    /** @return SessionInterface[] */
    private function fetchAll(int|string $userId): array
    {
        self::assertUserId($userId);
        $now = $this->dateTimeFactory->now();
        $formattedNow = $now->format($this->config->dateFormat);

        $rows = $this->database
            ->select()
            ->from($this->config->table)
            ->where($this->config->userIdColumn, $userId)
            ->where($this->config->replacedByColumn, null)
            ->where($this->config->absoluteExpiresAtColumn, '>', $formattedNow)
            ->where($this->config->expiresAtColumn, '>', $formattedNow)
            ->orderBy($this->config->lastActiveAtColumn, 'DESC')
            ->run()
            ->fetchAll();

        return array_map($this->hydrate(...), $rows);
    }

    /** @param array<string, mixed> $row */
    private function hydrate(array $row): SessionInterface
    {
        return new Session(
            id: (string) $row[$this->config->idColumn],
            userId: $row[$this->config->userIdColumn],
            expiresAt: $this->dateTimeFactory->parse(
                $row[$this->config->expiresAtColumn],
            ),
            absoluteExpiresAt: $this->dateTimeFactory->parse(
                $row[$this->config->absoluteExpiresAtColumn],
            ),
            regenerateAt: $this->dateTimeFactory->parse(
                $row[$this->config->regenerateAtColumn],
            ),
            replacedBy: isset($row[$this->config->replacedByColumn])
                ? (string) $row[$this->config->replacedByColumn]
                : null,
            createdAt: $this->dateTimeFactory->parse(
                $row[$this->config->createdAtColumn],
            ),
            lastActiveAt: $this->dateTimeFactory->parse(
                $row[$this->config->lastActiveAtColumn],
            ),
            attributes: json_decode(
                (string) $row[$this->config->attributesColumn],
                true,
                512,
                JSON_THROW_ON_ERROR,
            ),
        );
    }
}
