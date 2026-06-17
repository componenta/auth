<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Auth\AuthSubject;
use Componenta\Auth\Exception\TransportException;
use Componenta\Auth\Exception\UserProviderException;

/**
 * Handles the request step of a token-based flow.
 *
 * Looks up the user by identity, revokes existing tokens,
 * generates a new token, and sends it via the configured sender.
 *
 * Used for magic links, password resets, and similar flows.
 *
 * To prevent user enumeration, the calling handler should
 * return a success response regardless of this method's return value.
 */
final readonly class TokenRequester
{
    public function __construct(
        private UserProviderInterface $provider,
        private TokenManagerInterface $tokenManager,
        private SenderInterface $sender,
    ) {}

    /**
     * Generates a token and sends it to the user.
     *
     * Revokes all existing tokens for the user before generating a new one.
     *
     * @param string $identity User identity (email, phone number)
     * @param string|null $destination Delivery address; defaults to identity
     * @param array<string, string> $context Extra key-value pairs forwarded to the sender
     * @return bool True if user exists and token was sent
     *
     * @throws UserProviderException On infrastructure error in user lookup
     * @throws TransportException On send failure
     */
    public function request(string $identity, ?string $destination = null, array $context = []): bool
    {
        $user = $this->provider->findByIdentity($identity);

        if ($user === null) {
            return false;
        }

        $subjectId = (string) AuthSubject::id($user);

        $this->tokenManager->revokeForUser($subjectId);
        $token = $this->tokenManager->generate($subjectId);
        $this->sender->send($destination ?? $identity, $token, $context);

        return true;
    }
}
