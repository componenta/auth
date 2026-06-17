<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Auth\Exception\TransportException;

/**
 * Sends a token to the user via a delivery channel (email, SMS, etc.).
 *
 * The library provides the raw token. The implementation decides
 * the full URL format and delivery method.
 */
interface SenderInterface
{
    /**
     * Sends the token to the specified destination.
     *
     * @param string $destination Recipient address (email, phone number)
     * @param string $token Plain token to include in the URL
     * @param array<string, string> $context Extra key-value pairs for the URL
     *
     * @throws TransportException On send failure
     */
    public function send(string $destination, string $token, array $context = []): void;
}
