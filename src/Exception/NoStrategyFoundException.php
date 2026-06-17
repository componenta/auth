<?php

declare(strict_types=1);

namespace Componenta\Auth\Exception;

/**
 * Thrown when no authentication strategy supports the payload.
 *
 * This typically indicates a misconfiguration where no strategy
 * is registered for the given extractor type.
 *
 * Only the payload type name is retained - the payload instance itself
 * is not stored to keep secrets (passwords, tokens) out of exception traces.
 */
class NoStrategyFoundException extends AuthenticationException
{
    public readonly string $payloadType;

    public function __construct(object $payload)
    {
        $this->payloadType = $payload::class;

        parent::__construct(
            sprintf('No authentication strategy supports payload of type %s', $this->payloadType),
        );
    }
}
