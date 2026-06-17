<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/**
 * Generates cryptographically secure random numeric codes.
 */
final readonly class CodeGenerator
{
    public function __construct(
        private OtpConfig $config,
    ) {}

    /**
     * @throws \Random\RandomException
     */
    public function generate(): string
    {
        // Full decimal range 0..10^length-1 with leading-zero padding.
        // The previous implementation used 10^(length-1)..10^length-1,
        // which silently excluded ~10% of possible codes (those starting
        // with 0) and noticeably shrank the keyspace for short lengths.
        $max = (int) (10 ** $this->config->length) - 1;

        return str_pad(
            (string) random_int(0, $max),
            $this->config->length,
            '0',
            STR_PAD_LEFT,
        );
    }
}
