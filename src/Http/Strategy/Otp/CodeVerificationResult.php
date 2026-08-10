<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

final readonly class CodeVerificationResult
{
    private function __construct(
        public CodeVerificationStatus $status,
        public ?string $userId = null,
    ) {}

    public static function verified(string $userId): self
    {
        return new self(CodeVerificationStatus::Verified, $userId);
    }

    public static function invalid(): self
    {
        return new self(CodeVerificationStatus::Invalid);
    }

    public static function expired(): self
    {
        return new self(CodeVerificationStatus::Expired);
    }

    public static function tooManyAttempts(): self
    {
        return new self(CodeVerificationStatus::TooManyAttempts);
    }
}
