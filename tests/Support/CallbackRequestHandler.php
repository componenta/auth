<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Support;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class CallbackRequestHandler implements RequestHandlerInterface
{
    /** @param \Closure(ServerRequestInterface): ResponseInterface $callback */
    public function __construct(private \Closure $callback) {}

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return ($this->callback)($request);
    }
}
