<?php

declare(strict_types=1);

namespace Componenta\Auth;

/**
 * Contains metadata about the authentication request.
 *
 * Context provides a flexible key-value store for request metadata
 * such as the extractor instance, IP address, user agent, etc.
 *
 * The EXTRACTOR attribute is set by the extractor that created the payload
 * and is used by authentication strategies to determine if they support
 * the payload.
 */
interface ContextInterface
{
    /**
     * The extractor instance that created the payload.
     *
     * Value is an object implementing the protocol-specific
     * PayloadExtractorInterface (e.g., Http\PayloadExtractorInterface).
     *
     * If the extractor also implements PayloadStorageInterface
     * (i.e., is a TransportInterface), the instance can be used
     * to store/remove payload data in the response.
     *
     * This allows AuthenticationStrategyInterface to:
     * - Determine extractor type via instanceof
     * - Access extractor configuration (e.g., field names)
     *
     * @see Http\PayloadExtractorInterface
     * @see Http\PayloadStorageInterface
     * @see Http\TransportInterface
     */
    public const string EXTRACTOR = '__extractor';

    /**
     * Returns the value of the given attribute.
     *
     * @param string $key The attribute key
     * @param mixed $default The default value if attribute doesn't exist
     * @return mixed The attribute value or default
     */
    public function getAttribute(string $key, mixed $default = null): mixed;

    /**
     * Checks if the given attribute exists.
     */
    public function hasAttribute(string $key): bool;

    /**
     * Returns all attributes.
     *
     * @return array<string, mixed>
     */
    public function getAttributes(): array;

    /**
     * Returns a new instance with the given attribute.
     */
    public function withAttribute(string $key, mixed $value): static;

    /**
     * Returns a new instance with the given attributes merged.
     *
     * @param array<string, mixed> $attributes
     */
    public function withAttributes(array $attributes): static;
}
