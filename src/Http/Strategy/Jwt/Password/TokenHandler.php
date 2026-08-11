<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\Password;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Authenticates a password payload through the configured authenticator. */
final readonly class TokenHandler implements RequestHandlerInterface
{
    public function __construct(
        private PasswordExtractor $extractor,
        private AuthenticatorInterface $authenticator,
        private TokenPairResponse $tokenPair,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
    ) {}

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $payload = $this->extractor->extract($request);
        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return $this->deniedResponseFactory->create($result->subject);
        }

        return $this->tokenPair->create($result->subject);
    }
}
