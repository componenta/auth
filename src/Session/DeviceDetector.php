<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * Extracts device metadata (OS, browser, device type) from User-Agent string.
 *
 * Provides lightweight UA parsing without external dependencies.
 * Returns structured array suitable for session attributes.
 */
final class DeviceDetector
{
    public const string ATTR_OS = 'os';
    public const string ATTR_BROWSER = 'browser';
    public const string ATTR_DEVICE_TYPE = 'device_type';

    /**
     * Parses a User-Agent string and returns device metadata.
     *
     * @return array{os: string, browser: string, device_type: string}
     */
    public function detect(string $userAgent): array
    {
        return [
            self::ATTR_OS => $this->detectOs($userAgent),
            self::ATTR_BROWSER => $this->detectBrowser($userAgent),
            self::ATTR_DEVICE_TYPE => $this->detectDeviceType($userAgent),
        ];
    }

    private function detectOs(string $ua): string
    {
        return match (true) {
            str_contains($ua, 'iPhone'), str_contains($ua, 'iPad') => 'iOS',
            str_contains($ua, 'Android') => 'Android',
            str_contains($ua, 'Windows') => 'Windows',
            str_contains($ua, 'Mac OS') => 'macOS',
            str_contains($ua, 'Linux') => 'Linux',
            str_contains($ua, 'CrOS') => 'Chrome OS',
            default => 'Unknown',
        };
    }

    private function detectBrowser(string $ua): string
    {
        return match (true) {
            str_contains($ua, 'Edg/') => 'Edge',
            str_contains($ua, 'OPR/'), str_contains($ua, 'Opera') => 'Opera',
            str_contains($ua, 'YaBrowser') => 'Yandex',
            str_contains($ua, 'Firefox/') => 'Firefox',
            str_contains($ua, 'Chrome/') => 'Chrome',
            str_contains($ua, 'Safari/') && !str_contains($ua, 'Chrome') => 'Safari',
            default => 'Unknown',
        };
    }

    private function detectDeviceType(string $ua): string
    {
        return match (true) {
            str_contains($ua, 'iPhone'), str_contains($ua, 'Android') && str_contains($ua, 'Mobile') => 'mobile',
            str_contains($ua, 'iPad'), str_contains($ua, 'Android') && !str_contains($ua, 'Mobile') => 'tablet',
            default => 'desktop',
        };
    }
}
