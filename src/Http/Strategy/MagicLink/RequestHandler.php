<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

use Componenta\Auth\Token\TokenRequester;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles magic link request (send) step.
 *
 * Extracts the user identity from the request body and
 * delegates to MagicLinkRequester to generate and send the token.
 *
 * Always returns 200 regardless of whether the user exists,
 * to prevent user enumeration attacks.
 */
final readonly class RequestHandler implements RequestHandlerInterface
{
    public function __construct(
        private TokenRequester $requester,
        private ResponseFactoryInterface $responseFactory,
        private string $identityField = 'identity',
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = $request->getParsedBody() ?? [];

        if (!is_array($body)) {
            $body = get_object_vars($body);
        }

        $identity = $body[$this->identityField] ?? null;

        if ($identity === null || $identity === '') {
            $response = $this->responseFactory->createResponse(400);
            $response->getBody()->write(
                json_encode(['error' => 'missing_identity'], JSON_THROW_ON_ERROR)
            );

            return $response->withHeader('Content-Type', 'application/json');
        }

        $context = [];
        $redirect = $body['redirect'] ?? null;

        if (is_string($redirect) && $redirect !== '') {
            $context['redirect'] = $redirect;
        }

        $this->requester->request($identity, context: $context);

        $response = $this->responseFactory->createResponse(200);
        $response->getBody()->write(json_encode([
            'message' => 'If the account exists, a link has been sent.',
        ], JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
