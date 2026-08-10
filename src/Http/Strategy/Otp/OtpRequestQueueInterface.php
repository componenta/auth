<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

interface OtpRequestQueueInterface
{
    public function enqueue(OtpRequest $request): void;
}
