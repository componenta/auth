<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/**
 * Queue for the uniform OTP request path.
 *
 * Production adapters should be durable and non-inline when account-existence
 * timing matters: provider lookup, challenge persistence and delivery must not
 * become part of the public request latency.
 *
 * Workers must serialize requests for the same identity in enqueue order. The
 * built-in store intentionally keeps only one current challenge per
 * destination, so concurrent workers for one identity could otherwise replace
 * challenge A with B and still deliver A after B, making the last-delivered OTP
 * already invalid.
 */
interface OtpRequestQueueInterface
{
    public function enqueue(OtpRequest $request): void;
}
