<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Support;

use Psr\Http\Message\UriInterface;

/**
 * Minimal UriInterface fake for tests. Only identity is meaningful - the
 * resolvers under test receive the URI but do not introspect it.
 */
final class UriFixture implements UriInterface
{
    public function __construct(private string $path = '/') {}

    public function getScheme(): string { return ''; }
    public function getAuthority(): string { return ''; }
    public function getUserInfo(): string { return ''; }
    public function getHost(): string { return ''; }
    public function getPort(): ?int { return null; }
    public function getPath(): string { return $this->path; }
    public function getQuery(): string { return ''; }
    public function getFragment(): string { return ''; }

    public function withScheme(string $scheme): UriInterface { return $this; }
    public function withUserInfo(string $user, ?string $password = null): UriInterface { return $this; }
    public function withHost(string $host): UriInterface { return $this; }
    public function withPort(?int $port): UriInterface { return $this; }
    public function withPath(string $path): UriInterface
    {
        $clone = clone $this;
        $clone->path = $path;
        return $clone;
    }
    public function withQuery(string $query): UriInterface { return $this; }
    public function withFragment(string $fragment): UriInterface { return $this; }

    public function __toString(): string { return $this->path; }
}
