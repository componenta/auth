<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Componenta\Auth\DeniedReasonInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Creates HTTP response from denied reason.
 */
interface DeniedResponseFactoryInterface
{
    /**
     * Creates response for the given denial reason.
     *
     * Implementations should map denial codes to appropriate
     * HTTP status codes and response bodies.
     */
    public function create(DeniedReasonInterface $reason): ResponseInterface;
}
