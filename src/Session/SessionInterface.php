<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * Represents an active user session.
 *
 * A session tracks user authentication state across requests.
 * Sessions are created after successful authentication and
 * can be terminated on logout or security events.
 *
 * Metadata (attributes) can store request context such as
 * IP address, user agent, device type, or location.
 */
interface SessionInterface
{
    /**
     * Unique session identifier.
     *
     * Used for session lookup, storage, and cookie value.
     * Should be cryptographically secure to prevent guessing.
     *
     * @see SessionIdGeneratorInterface
     */
    public string $id { get; }

    /**
     * Identifier of the authenticated user.
     *
     * References the user who owns this session.
     */
    public int|string $userId { get; }

    /**
     * Idle timeout expiration (sliding).
     *
     * Updated on each request via touch().
     */
    public \DateTimeImmutable $expiresAt { get; }

    /**
     * Absolute timeout expiration (fixed).
     *
     * Set once at creation, forces re-authentication.
     */
    public \DateTimeImmutable $absoluteExpiresAt { get; }

    /**
     * Next session ID regeneration time (canary).
     */
    public \DateTimeImmutable $regenerateAt { get; }

    /**
     * ID of the replacement session after regeneration.
     *
     * Non-null means this session was replaced.
     * Old session remains valid during grace period.
     */
    public ?string $replacedBy { get; }

    /**
     * Timestamp when the session was created.
     *
     * Set once during session creation, never changes.
     */
    public \DateTimeImmutable $createdAt { get; }

    /**
     * Timestamp of last session activity.
     *
     * Updated via SessionManagerInterface::touch() on each request.
     * Used for session expiration and "last seen" display.
     */
    public \DateTimeImmutable $lastActiveAt { get; }

    /**
     * Checks if an attribute exists.
     */
    public function hasAttribute(string $name): bool;

    /**
     * Returns a session metadata value.
     *
     * @param string $name Attribute name
     * @param mixed $default Value returned if attribute doesn't exist
     * @return mixed Attribute value or default
     */
    public function getAttribute(string $name, mixed $default = null): mixed;

    /**
     * Returns all session metadata.
     *
     * Common attributes:
     * - ip: Client IP address
     * - user_agent: Browser/client identifier
     * - device: Device type (desktop, mobile, tablet)
     * - location: Geographic location
     *
     * @return array<string, mixed>
     */
    public function getAttributes(): array;
}