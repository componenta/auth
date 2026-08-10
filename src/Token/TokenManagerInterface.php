<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

interface TokenManagerInterface
{
    public function generate(string $userId): string;
    public function find(string $plainToken): ?Token;
    public function consume(string $plainToken): bool;
    public function revokeForUser(string $userId): void;
    public function cleanup(int $limit = 1000): int;
}
