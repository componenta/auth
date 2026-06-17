<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\Password;

use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\Http\Strategy\Password\PasswordStrategy;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles password-based login and issues a JWT token pair.
 *
 * Extracts credentials via PasswordExtractor, authenticates
 * via PasswordStrategy, and returns access + refresh tokens.
 */
final readonly class TokenHandler implements RequestHandlerInterface
{
    public function __construct(
        private PasswordExtractor $extractor,
        private PasswordStrategy $strategy,
        private TokenPairResponse $tokenPair,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $payload = $this->extractor->extract($request);

        $result = $this->strategy->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return $this->deniedResponseFactory->create($result->subject);
        }

        return $this->tokenPair->create($result->subject);
    }
}
