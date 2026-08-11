<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Event\SessionsTerminated;
use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\DeleteQuery;
use Cycle\Database\Query\SelectQuery;

final readonly class DatabaseSessionManager implements SessionManagerInterface
{
    public const string ATTR_IP = 'ip';
    public const string ATTR_USER_AGENT = 'user_agent';

    private const int MAX_SESSION_ID_LENGTH = 512;
    private const int MAX_IP_LENGTH = 45;
    private const int MAX_USER_AGENT_LENGTH = 1024;
    private const int MAX_ATTRIBUTES_JSON_LENGTH = 16384;
    private const int DELETE_CHUNK_SIZE = 500;
    private const int MAX_CLEANUP_LIMIT = 10000;

    private DateTimeFactoryInterface $dateTimeFactory;

    public function __construct(
        private DatabaseInterface $database,
        private SessionIdGeneratorInterface $idGenerator,
        DateTimeFactoryInterface $dateTimeFactory,
        private EventDispatcher $dispatcher,
        private DatabaseSessionManagerConfig $config = new DatabaseSessionManagerConfig(),
    ) {
        $this->dateTimeFactory = $dateTimeFactory->withTimezone('UTC');
    }

    #[\Override]
    public function create(UuidInterface $subjectId, array $attributes = []): SessionInterface
    {
        $ip = $attributes[self::ATTR_IP]
            ?? throw new \InvalidArgumentException('Missing required attribute: ' . self::ATTR_IP);
        $userAgent = $attributes[self::ATTR_USER_AGENT]
            ?? throw new \InvalidArgumentException(
                'Missing required attribute: ' . self::ATTR_USER_AGENT,
            );

        if (
            !is_string($ip)
            || strlen($ip) > self::MAX_IP_LENGTH
            || ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) === false)
        ) {
            throw new \InvalidArgumentException(
                'Session IP attribute must be a bounded string.',
            );
        }

        if (
            !is_string($userAgent)
            || strlen($userAgent) > self::MAX_USER_AGENT_LENGTH
            || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $userAgent) === 1
        ) {
            throw new \InvalidArgumentException(
                'Session User-Agent attribute must be a bounded string.',
            );
        }

        $sessionId = $this->idGenerator->generate();
        self::assertSessionId($sessionId);
        $now = $this->dateTimeFactory->now();

        $session = new Session(
            id: $sessionId,
            subjectId: $subjectId,
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
        $query = $this->database->select('1')->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        );

        if (!$query instanceof SelectQuery) {
            throw new \LogicException(
                'Cycle must preserve SelectQuery when pinning the write driver.',
            );
        }

        return $query
            ->from($this->config->table)
            ->where($this->config->idColumn, $sessionId)
            ->run()
            ->fetch() !== false;
    }

    #[\Override]
    public function find(string $sessionId): ?SessionInterface
    {
        self::assertSessionId($sessionId);
        $query = $this->database->select()->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        );

        if (!$query instanceof SelectQuery) {
            throw new \LogicException(
                'Cycle must preserve SelectQuery when pinning the write driver.',
            );
        }

        $row = $query
            ->from($this->config->table)
            ->where($this->config->idColumn, $sessionId)
            ->run()
            ->fetch();

        if (!is_array($row)) {
            return null;
        }

        $session = $this->hydrate($row);
        $now = $this->dateTimeFactory->now();

        if (
            $session->replacedBy !== null
            || $session->absoluteExpiresAt <= $now
            || $session->expiresAt <= $now
        ) {
            return null;
        }

        return $session;
    }

    #[\Override]
    public function all(UuidInterface $subjectId): SessionCollectionInterface
    {
        if ($this->config->lazyLoad) {
            $reflector = new \ReflectionClass(SessionCollection::class);

            return $reflector->newLazyGhost(
                function (SessionCollection $ghost) use ($subjectId): void {
                    $ghost->__construct($this->fetchAll($subjectId));
                },
            );
        }

        return new SessionCollection($this->fetchAll($subjectId));
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

        $event = new SessionsTerminated($ids);

        $this->database->transaction(function () use ($ids, $event): void {
            foreach (array_chunk($ids, self::DELETE_CHUNK_SIZE) as $chunk) {
                $this->database
                    ->delete($this->config->table)
                    ->where($this->config->idColumn, 'IN', $chunk)
                    ->run();
            }

            $this->dispatcher->dispatchCritical($event);
        });

        $this->dispatcher->dispatchBestEffort($event);
    }

    #[\Override]
    public function terminateAll(UuidInterface $subjectId, ?string $exceptSessionId = null): void
    {
        if ($exceptSessionId !== null) {
            self::assertSessionId($exceptSessionId);
        }

        $event = new AllSessionsTerminated($subjectId, $exceptSessionId);

        $this->database->transaction(function () use ($subjectId, $exceptSessionId, $event): void {
            $query = $this->database
                ->delete($this->config->table)
                ->where($this->config->subjectIdColumn, $subjectId->toString());

            if ($exceptSessionId !== null) {
                $query->where($this->config->idColumn, '!=', $exceptSessionId);
            }

            $query->run();
            $this->dispatcher->dispatchCritical($event);
        });

        $this->dispatcher->dispatchBestEffort($event);
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
            ->where(function (mixed $query) use ($now): void {
                if (!$query instanceof SelectQuery) {
                    throw new \LogicException('Cycle must provide a SelectQuery to the predicate.');
                }

                $query
                    ->where($this->config->expiresAtColumn, '<=', $now)
                    ->orWhere($this->config->absoluteExpiresAtColumn, '<=', $now);
            })
            ->limit($limit)
            ->run()
            ->fetchAll();

        $ids = [];

        foreach ($rows as $row) {
            if (is_array($row)) {
                $ids[] = self::stringValue($row, $this->config->idColumn);
            }
        }

        if ($ids === []) {
            return 0;
        }

        $deleted = 0;

        foreach (array_chunk($ids, self::DELETE_CHUNK_SIZE) as $chunk) {
            $deleted += $this->database
                ->delete($this->config->table)
                ->where($this->config->idColumn, 'IN', $chunk)
                ->where(function (mixed $query) use ($now): void {
                    if (!$query instanceof DeleteQuery) {
                        throw new \LogicException('Cycle must provide a DeleteQuery to the predicate.');
                    }

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
        $query = $this->database->select()->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        );

        if (!$query instanceof SelectQuery) {
            throw new \LogicException(
                'Cycle must preserve SelectQuery when pinning the write driver.',
            );
        }

        $row = $query
            ->from($this->config->table)
            ->where($this->config->idColumn, $sessionId)
            ->run()
            ->fetch();

        if (!is_array($row)) {
            throw new \InvalidArgumentException('Session not found');
        }

        $old = $this->hydrate($row);
        $now = $this->dateTimeFactory->now();

        if ($old->replacedBy !== null) {
            throw new ConcurrentRegenerationException();
        }

        if ($old->absoluteExpiresAt <= $now || $old->expiresAt <= $now) {
            throw new \InvalidArgumentException('Session expired');
        }

        $newSessionId = $this->idGenerator->generate();
        self::assertSessionId($newSessionId);
        $idleExpiresAt = $now->modify("+{$this->config->idleTimeout} seconds");

        $new = new Session(
            id: $newSessionId,
            subjectId: $old->subjectId,
            expiresAt: $idleExpiresAt < $old->absoluteExpiresAt
                ? $idleExpiresAt
                : $old->absoluteExpiresAt,
            absoluteExpiresAt: $old->absoluteExpiresAt,
            regenerateAt: $now->modify("+{$this->config->regenerationInterval} seconds"),
            replacedBy: null,
            createdAt: $now,
            lastActiveAt: $now,
            attributes: $old->attributes,
        );
        $event = new SessionRegenerated($sessionId, $new->id);
        $formattedNow = $now->format($this->config->dateFormat);

        $this->database->transaction(function () use (
            $sessionId,
            $new,
            $now,
            $formattedNow,
            $event,
        ): void {
            $ip = $new->getAttribute(self::ATTR_IP);
            $userAgent = $new->getAttribute(self::ATTR_USER_AGENT);

            if (!is_string($ip) || !is_string($userAgent)) {
                throw new \UnexpectedValueException(
                    'Regenerated session is missing transport metadata.',
                );
            }

            $this->insert($new, $ip, $userAgent);

            $affectedRows = $this->database
                ->update($this->config->table)
                ->where($this->config->idColumn, $sessionId)
                ->where($this->config->replacedByColumn, null)
                ->where($this->config->expiresAtColumn, '>', $formattedNow)
                ->where($this->config->absoluteExpiresAtColumn, '>', $formattedNow)
                ->values([
                    $this->config->replacedByColumn => $new->id,
                    $this->config->expiresAtColumn => $now
                        ->modify("+{$this->config->regenerationGracePeriod} seconds")
                        ->format($this->config->dateFormat),
                ])
                ->run();

            if ($affectedRows !== 1) {
                throw new ConcurrentRegenerationException();
            }

            $this->dispatcher->dispatchCritical($event);
        });

        $this->dispatcher->dispatchBestEffort($event);

        return $new;
    }

    private function insert(SessionInterface $session, string $ip, string $userAgent): void
    {
        $attributes = $session->attributes;
        unset(
            $attributes[self::ATTR_IP],
            $attributes[self::ATTR_USER_AGENT],
        );

        $attributesJson = json_encode($attributes, JSON_THROW_ON_ERROR);

        if (strlen($attributesJson) > self::MAX_ATTRIBUTES_JSON_LENGTH) {
            throw new \InvalidArgumentException(sprintf(
                'Session attributes must not exceed %d JSON bytes.',
                self::MAX_ATTRIBUTES_JSON_LENGTH,
            ));
        }

        $this->database
            ->insert($this->config->table)
            ->values([
                $this->config->idColumn => $session->id,
                $this->config->subjectIdColumn => $session->subjectId->toString(),
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
                $this->config->attributesColumn => $attributesJson,
            ])
            ->run();
    }

    /**
     * @param string|iterable<string>|SessionCollectionInterface $sessionId
     * @return list<string>
     */
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

    private static function assertSessionId(string $sessionId): void
    {
        if (
            $sessionId === ''
            || strlen($sessionId) > self::MAX_SESSION_ID_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $sessionId) === 1
        ) {
            throw new \InvalidArgumentException(sprintf(
                'Session ID must contain between 1 and %d bytes.',
                self::MAX_SESSION_ID_LENGTH,
            ));
        }
    }

    /** @return SessionInterface[] */
    private function fetchAll(UuidInterface $subjectId): array
    {
        $now = $this->dateTimeFactory->now();
        $formattedNow = $now->format($this->config->dateFormat);
        $query = $this->database->select()->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        );

        if (!$query instanceof SelectQuery) {
            throw new \LogicException(
                'Cycle must preserve SelectQuery when pinning the write driver.',
            );
        }

        $rows = $query
            ->from($this->config->table)
            ->where($this->config->subjectIdColumn, $subjectId->toString())
            ->where($this->config->replacedByColumn, null)
            ->where($this->config->absoluteExpiresAtColumn, '>', $formattedNow)
            ->where($this->config->expiresAtColumn, '>', $formattedNow)
            ->orderBy($this->config->lastActiveAtColumn, 'DESC')
            ->run()
            ->fetchAll();

        $sessions = [];

        foreach ($rows as $row) {
            if (is_array($row)) {
                $sessions[] = $this->hydrate($row);
            }
        }

        return $sessions;
    }

    /** @param array<array-key, mixed> $row */
    private function hydrate(array $row): SessionInterface
    {
        $replacedBy = $row[$this->config->replacedByColumn] ?? null;
        $attributesJson = self::stringValue($row, $this->config->attributesColumn);
        $attributes = json_decode(
            $attributesJson,
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        if (!is_array($attributes)) {
            throw new \UnexpectedValueException(
                'Session attributes must decode to an object-like array.',
            );
        }

        /** @var array<string, mixed> $attributes */
        $attributes[self::ATTR_IP] = self::stringValue(
            $row,
            $this->config->ipColumn,
        );
        $attributes[self::ATTR_USER_AGENT] = self::stringValue(
            $row,
            $this->config->userAgentColumn,
        );

        return new Session(
            id: self::stringValue($row, $this->config->idColumn),
            subjectId: Uuid::fromString(self::stringValue(
                $row,
                $this->config->subjectIdColumn,
            )),
            expiresAt: $this->dateTimeFactory->parse(self::stringValue(
                $row,
                $this->config->expiresAtColumn,
            )),
            absoluteExpiresAt: $this->dateTimeFactory->parse(self::stringValue(
                $row,
                $this->config->absoluteExpiresAtColumn,
            )),
            regenerateAt: $this->dateTimeFactory->parse(self::stringValue(
                $row,
                $this->config->regenerateAtColumn,
            )),
            replacedBy: $replacedBy === null
                ? null
                : self::stringValue($row, $this->config->replacedByColumn),
            createdAt: $this->dateTimeFactory->parse(self::stringValue(
                $row,
                $this->config->createdAtColumn,
            )),
            lastActiveAt: $this->dateTimeFactory->parse(self::stringValue(
                $row,
                $this->config->lastActiveAtColumn,
            )),
            attributes: $attributes,
        );
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(sprintf(
                'Database column "%s" must contain a string-compatible value.',
                $key,
            ));
        }

        return (string) $value;
    }
}
