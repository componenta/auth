<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Identity\UuidInterface;

final readonly class CodeVerificationResult
{
    private function __construct(
        public CodeVerificationStatus $status,
        public ?UuidInterface $subjectId = null,
    ) {}

    public static function verified(UuidInterface $subjectId): self
    {
        return new self(CodeVerificationStatus::Verified, $subjectId);
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
