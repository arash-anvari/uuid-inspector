<?php
namespace ArashAnvari\UuidInspector;

use DateTimeImmutable;
use DateTimeZone;

class UuidInspector
{
    public static function parse(string $uuid, ?string $opt = null): array|string
    {
        $orig = $uuid;
        $uuid = strtolower(trim($uuid));

        $res = [
            'input' => $orig,
            'normalized' => null,
            'valid' => false,
            'version' => null,
            'variant' => null,
            'parts' => null,
            'hex' => null,
            'binary' => null,
            'base64' => null,
            'is_nil' => false,
            'is_max' => false,
            'notes' => [],
            'detail' => [],
            'representations' => [],
            'encodings' => [],
            'bit_analysis' => [],
            'environment' => [],
        ];

        if (!preg_match('/^[0-9a-f]{8}(-?[0-9a-f]{4}){3}-?[0-9a-f]{12}$/', $uuid)) {
            $res['notes'][] = 'Invalid UUID format (expected 32 hex w/ optional dashes).';
            return self::finalize($res, $opt);
        }

        if (strpos($uuid, '-') === false) {
            $uuid = substr($uuid, 0, 8) . '-' .
                substr($uuid, 8, 4) . '-' .
                substr($uuid, 12, 4) . '-' .
                substr($uuid, 16, 4) . '-' .
                substr($uuid, 20, 12);
        }

        $res['normalized'] = $uuid;
        $res['valid'] = true;

        $parts = explode('-', $uuid);
        $res['parts'] = $parts;
        $res['hex'] = implode('', $parts);
        $res['binary'] = hex2bin($res['hex']);
        $res['base64'] = base64_encode($res['binary']);

        if (preg_match('/^0+$/', $res['hex'])) {
            $res['is_nil'] = true;
            $res['notes'][] = 'Nil UUID (all zeros).';
        }
        if (preg_match('/^f+$/', $res['hex'])) {
            $res['is_max'] = true;
            $res['notes'][] = 'All-ones UUID (all f).';
        }

        $time_low = hexdec($parts[0]);
        $time_mid = hexdec($parts[1]);
        $time_hi_and_version = hexdec($parts[2]);
        $clock_seq_hi_and_reserved = hexdec(substr($parts[3], 0, 2));
        $clock_seq_low = hexdec(substr($parts[3], 2, 2));
        $node_hex = $parts[4];

        $version = ($time_hi_and_version & 0xF000) >> 12;
        $res['version'] = (int)$version;

        if (($clock_seq_hi_and_reserved & 0x80) === 0x00) {
            $variant = 'NCS (0xx)';
        } elseif (($clock_seq_hi_and_reserved & 0xC0) === 0x80) {
            $variant = 'RFC 4122 (10x)';
        } elseif (($clock_seq_hi_and_reserved & 0xE0) === 0xC0) {
            $variant = 'Microsoft (110x)';
        } else {
            $variant = 'Future (111x)';
        }
        $res['variant'] = $variant;

        $res['detail'] = [
            'clock_seq_raw' => sprintf('%02x%02x', $clock_seq_hi_and_reserved, $clock_seq_low),
            'clock_seq_value' => (($clock_seq_hi_and_reserved & 0x3F) << 8) | $clock_seq_low,
            'node_raw' => $node_hex,
            'node' => implode(':', str_split($node_hex, 2)),
        ];

        $first_octet = hexdec(substr($node_hex, 0, 2));
        $res['detail']['node_is_multicast'] = (bool)($first_octet & 0x01);
        $res['detail']['node_is_locally_administered'] = (bool)($first_octet & 0x02);

        $res = self::addIntegerRepresentations($res);

        $res['bit_analysis'] = [
            'version_bits' => sprintf('%04b', $version),
            'variant_bits' => sprintf('%02b', ($clock_seq_hi_and_reserved >> 6)),
        ];

        $res['environment'] = [
            'php_version' => PHP_VERSION,
            'gmp' => extension_loaded('gmp'),
            'bcmath' => extension_loaded('bcmath'),
            'php_int_size' => PHP_INT_SIZE * 8,
        ];

        $res = self::analyzeByVersion($res, $version, $time_low, $time_mid, $time_hi_and_version, $node_hex);

        $res['representations'] = [
            'urn' => 'urn:uuid:' . $res['normalized'],
            'uppercase' => strtoupper($res['normalized']),
            'compact' => str_replace('-', '', $res['normalized']),
            'braced' => '{' . $res['normalized'] . '}',
        ];

        $res['encodings']['base36'] = self::baseConvert($res['hex'], 16, 36);
        $res['encodings']['base58'] = self::baseConvert($res['hex'], 16, 58);

        $res['summary'] = sprintf(
            'UUID %s — version: %s, variant: %s%s',
            $res['normalized'],
            $res['version'],
            $res['variant'],
            isset($res['detail']['v1']) ? ', v1 time parsed' : ''
        );

        return self::finalize($res, $opt);
    }

    public static function commonNamespaces(): array
    {
        return [
            'dns' => '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
            'url' => '6ba7b811-9dad-11d1-80b4-00c04fd430c8',
            'oid' => '6ba7b812-9dad-11d1-80b4-00c04fd430c8',
            'x500' => '6ba7b814-9dad-11d1-80b4-00c04fd430c8',
        ];
    }

    public static function isValid(string $uuid): bool
    {
        $uuid = strtolower(trim($uuid));

        $uuid = str_replace('-', '', $uuid);

        if (strlen($uuid) !== 32 || !ctype_xdigit($uuid)) {
            return false;
        }

        $binary = hex2bin($uuid);
        if ($binary === false || strlen($binary) !== 16) {
            return false;
        }

        $time_hi_and_version = ord($binary[6]) << 8 | ord($binary[7]);
        $clock_seq_hi_and_reserved = ord($binary[8]);

        $version = ($time_hi_and_version >> 12) & 0x0F;
        $variantBits = ($clock_seq_hi_and_reserved >> 6) & 0x03;

        if ($variantBits !== 0b10) {
            return false;
        }

        if (!in_array($version, [1, 2, 3, 4, 5, 6, 7, 8], true)) {
            return false;
        }

        if ($uuid === str_repeat('0', 32)) {
            return false;
        }

        $uniqueBytes = count(array_unique(str_split(bin2hex($binary), 2)));
        if ($uniqueBytes < 8) {
            return false;
        }

        return true;
    }

    public static function version(string $uuid): ?int
    {
        $uuid = strtolower(trim(str_replace('-', '', $uuid)));

        if (strlen($uuid) !== 32 || !ctype_xdigit($uuid)) {
            return null;
        }

        $bin = @hex2bin($uuid);
        if ($bin === false || strlen($bin) !== 16) {
            return null;
        }

        $time_hi_and_version = (ord($bin[6]) << 8) | ord($bin[7]);
        $version = ($time_hi_and_version >> 12) & 0x0F;

        return in_array($version, [1, 2, 3, 4, 5, 6, 7, 8], true) ? $version : null;
    }

    public static function variant(string $uuid): ?string
    {
        $uuid = strtolower(trim(str_replace('-', '', $uuid)));

        if (strlen($uuid) !== 32 || !ctype_xdigit($uuid)) {
            return null;
        }

        $bin = @hex2bin($uuid);
        if ($bin === false || strlen($bin) !== 16) {
            return null;
        }

        $clock_seq_hi = ord($bin[8]);

        if (($clock_seq_hi & 0x80) === 0x00) {
            return 'NCS (reserved, pre-RFC4122)';
        } elseif (($clock_seq_hi & 0xC0) === 0x80) {
            return 'RFC 4122 (Leach–Salz)';
        } elseif (($clock_seq_hi & 0xE0) === 0xC0) {
            return 'Microsoft (GUID)';
        } elseif (($clock_seq_hi & 0xE0) === 0xE0) {
            return 'Future (reserved)';
        }

        return null;
    }

    public static function analyze(string $uuid, ?string $opt = null): array|string
    {
        $result = [
            'input' => $uuid,
            'valid' => false,
            'version' => null,
            'variant' => null,
            'is_nil' => false,
            'is_max' => false,
            'structure_ok' => false,
            'timestamp' => null,
            'mac_address' => null,
            'clock_seq' => null,
            'bit_pattern' => null,
            'errors' => [],
            'summary' => null,
        ];

        $uuid = strtolower(trim(str_replace('-', '', $uuid)));

        if (strlen($uuid) !== 32 || !ctype_xdigit($uuid)) {
            $result['errors'][] = 'Invalid UUID format (should be 32 hex chars).';
            return self::finalize($result, $opt);
        }

        $binary = @hex2bin($uuid);
        if ($binary === false || strlen($binary) !== 16) {
            $result['errors'][] = 'Invalid binary representation.';
            return self::finalize($result, $opt);
        }

        if ($uuid === str_repeat('0', 32)) {
            $result['is_nil'] = true;
            $result['errors'][] = 'Nil UUID (all zeros).';
        } elseif ($uuid === str_repeat('f', 32)) {
            $result['is_max'] = true;
            $result['errors'][] = 'Max UUID (all Fs).';
        }

        $time_hi_and_version = (ord($binary[6]) << 8) | ord($binary[7]);
        $clock_seq_hi = ord($binary[8]);
        $version = ($time_hi_and_version >> 12) & 0x0F;
        $result['version'] = in_array($version, [1, 2, 3, 4, 5, 6, 7, 8], true) ? $version : null;

        if (($clock_seq_hi & 0x80) === 0x00) $variant = 'NCS (reserved)';
        elseif (($clock_seq_hi & 0xC0) === 0x80) $variant = 'RFC 4122 (Leach–Salz)';
        elseif (($clock_seq_hi & 0xE0) === 0xC0) $variant = 'Microsoft (GUID)';
        else $variant = 'Future (reserved)';
        $result['variant'] = $variant;

        $result['structure_ok'] = $result['version'] && str_starts_with($variant, 'RFC');

        if (in_array($version, [1, 6], true)) {
            $time_low = unpack('N', substr($binary, 0, 4))[1];
            $time_mid = unpack('n', substr($binary, 4, 2))[1];
            $time_hi = $time_hi_and_version & 0x0FFF;

            $timestamp = ($time_hi << 48) | ($time_mid << 32) | $time_low;

            $unixTimeFloat = ($timestamp / 10000000) - 12219292800;
            $unixTime = (int)floor($unixTimeFloat); // timestamp کامل
            $micro = (int)(($unixTimeFloat - $unixTime) * 1000000); // microseconds دقیق

            if ($unixTime > 0 && $unixTime < time() + 31536000) {
                $result['timestamp'] = gmdate('Y-m-d H:i:s', $unixTime) . sprintf(".%06d UTC", $micro);
            } else {
                $result['errors'][] = 'Invalid timestamp range.';
            }

            $clock_seq = ((ord($binary[8]) & 0x3F) << 8) | ord($binary[9]);
            $result['clock_seq'] = $clock_seq;

            $node = substr($binary, 10, 6);
            $mac = strtoupper(implode(':', str_split(bin2hex($node), 2)));
            $result['mac_address'] = $mac;

            $isRandom = (ord($node[0]) & 0x01) === 1;
            if ($isRandom) {
                $result['errors'][] = 'Node field does not represent a real MAC address (locally administered).';
            }
        }

        $uniqueBytes = count(array_unique(str_split($uuid, 2)));
        if ($uniqueBytes < 8) {
            $result['errors'][] = 'Low byte entropy (possibly spoofed UUID).';
        }

        $result['valid'] = $result['structure_ok'] && empty($result['errors']);

        $result['bit_pattern'] = [
            'version_bits' => sprintf('%04b', $version),
            'variant_bits' => sprintf('%08b', $clock_seq_hi),
        ];

        $result['summary'] = sprintf(
            "UUID v%s (%s)%s%s%s",
            $result['version'] ?? 'unknown',
            $result['variant'] ?? 'unknown',
            $result['timestamp'] ? ', Time: ' . $result['timestamp'] : '',
            $result['mac_address'] ? ', Node: ' . $result['mac_address'] : '',
            $result['clock_seq'] !== null ? ', Seq: ' . $result['clock_seq'] : ''
        );

        return self::finalize($result, $opt);
    }

    protected static function analyzeByVersion($res, $version, $time_low, $time_mid, $time_hi_and_version, $node_hex): array
    {
        if ($version === 1) {
            $time_hi = $time_hi_and_version & 0x0fff;
            $timestamp_hex = sprintf('%03x%04x%08x', $time_hi, $time_mid, $time_low);

            [$timestamp_100ns, $unix_seconds, $micro, $datetime_utc] = self::parseTimestamp($timestamp_hex);

            $dt = new DateTimeImmutable($datetime_utc);
            $dt_local = $dt->setTimezone(new DateTimeZone(date_default_timezone_get()));

            $res['detail']['v1'] = [
                'timestamp_hex' => $timestamp_hex,
                'timestamp_100ns' => $timestamp_100ns,
                'unix_seconds' => $unix_seconds,
                'datetime_utc' => $dt->format('Y-m-d H:i:s.u'),
                'datetime_local' => $dt_local->format('Y-m-d H:i:s.u'),
                'datetime_iso' => $dt->format(DATE_ATOM),
                'age_human' => self::humanDiff($dt),
                'microseconds' => $micro,
                'clock_seq' => $res['detail']['clock_seq_value'],
                'node' => $res['detail']['node'],
                'node_raw' => $node_hex,
                'node_is_multicast' => $res['detail']['node_is_multicast'],
                'node_is_locally_administered' => $res['detail']['node_is_locally_administered'],
            ];
        } elseif ($version === 2) {
            $res['detail']['v2'] = [
                'type' => 'DCE Security (local domain and ID)',
                'note' => 'Limited parsing implemented. Used rarely.',
            ];
        } elseif ($version === 3 || $version === 5) {
            $res['detail']["v{$version}"] = [
                'type' => ($version === 3) ? 'name-based (MD5)' : 'name-based (SHA1)',
                'note' => 'Name-based UUIDs are not reversible.',
                'common_namespaces' => self::commonNamespaces(),
            ];
        } elseif ($version === 4) {
            $entropy = self::estimateEntropy($res['binary']);
            $res['detail']['v4'] = [
                'type' => 'random-based',
                'entropy_bits_estimated' => $entropy,
                'note' => 'Purely random UUID — no semantic info embedded.',
            ];
        } else {
            $res['notes'][] = "Unknown or unsupported UUID version: {$version}";
        }

        return $res;
    }

    protected static function addIntegerRepresentations($res): array
    {
        $hex128 = $res['hex'];

        if (extension_loaded('gmp')) {
            $g = gmp_init($hex128, 16);
            $res['detail']['int128_gmp'] = gmp_strval($g, 10);
        } elseif (extension_loaded('bcmath')) {
            $dec = '0';
            foreach (str_split($hex128) as $digit) {
                $dec = bcmul($dec, '16');
                $dec = bcadd($dec, (string)hexdec($digit));
            }
            $res['detail']['int128_bc'] = $dec;
        } elseif (PHP_INT_SIZE >= 8) {
            $high = hexdec(substr($hex128, 0, 16));
            $low = hexdec(substr($hex128, 16, 16));
            $res['detail']['int128_high64'] = $high;
            $res['detail']['int128_low64'] = $low;
        } else {
            $res['notes'][] = 'Cannot compute 128-bit integer (no GMP/BCMath).';
        }

        return $res;
    }

    protected static function parseTimestamp($timestamp_hex): array
    {
        if (extension_loaded('gmp')) {
            $ts_g = gmp_init($timestamp_hex, 16);
            $unix_epoch_offset = gmp_init('12219292800');
            $secs = gmp_div_q($ts_g, gmp_init('10000000'));
            $rem = gmp_mod($ts_g, gmp_init('10000000'));
            $unix_seconds = gmp_strval(gmp_sub($secs, $unix_epoch_offset));
            $micro = (int)(gmp_intval($rem) / 10);
            $dt = '@' . $unix_seconds;
        } else {
            $ts_dec = hexdec($timestamp_hex);
            $secs = (int)($ts_dec / 10000000);
            $unix_seconds = $secs - 12219292800;
            $micro = (int)(($ts_dec % 10000000) / 10);
            $dt = '@' . $unix_seconds;
        }
        $datetime_utc = (new DateTimeImmutable($dt))->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
        return [$ts_dec ?? gmp_strval($ts_g ?? ''), $unix_seconds, $micro, $datetime_utc];
    }

    protected static function estimateEntropy(string $binary): int
    {
        $entropy = 0;
        $bytes = unpack('C*', $binary);
        $total = count($bytes);
        $freq = array_count_values($bytes);
        foreach ($freq as $f) {
            $p = $f / $total;
            $entropy -= $p * log($p, 2);
        }
        return (int)round($entropy * $total);
    }

    protected static function humanDiff(DateTimeImmutable $dt): string
    {
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $diff = $now->getTimestamp() - $dt->getTimestamp();

        if ($diff < 60) return "{$diff} seconds ago";
        if ($diff < 3600) return floor($diff / 60) . " minutes ago";
        if ($diff < 86400) return floor($diff / 3600) . " hours ago";
        if ($diff < 2592000) return floor($diff / 86400) . " days ago";
        if ($diff < 31536000) return floor($diff / 2592000) . " months ago";
        return floor($diff / 31536000) . " years ago";
    }

    protected static function baseConvert(string $number, int $fromBase, int $toBase): string
    {
        if (extension_loaded('gmp')) {
            $g = gmp_init($number, $fromBase);
            return gmp_strval($g, $toBase);
        }
        return base_convert($number, $fromBase, $toBase);
    }

    protected static function finalize(array $res, ?string $format = 'array'): array|string
    {
        $format ??= 'array';

        $output = $res;

        if (in_array($format, ['json', 'json-pretty'], true) && isset($output['binary'])) {
            $output['binary'] = base64_encode($output['binary']);
        }

        return match ($format) {
            'json' => json_encode($output, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT),
            'json-pretty' => json_encode($output, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT),
            'yaml' => self::toYaml($res),
            'serialize' => serialize($res),
            'string' => self::summaryString($res),
            'pretty-table' => self::prettyTable($res),
            'xml' => self::arrayToXml($res),
            default => $res,
        };
    }

    protected static function toYaml(array $data, int $indent = 0): string
    {
        $lines = [];
        $indentStr = str_repeat('  ', $indent);

        foreach ($data as $key => $value) {
            if (!is_int($key)) {
                $safeKey = (string)$key;
                if (preg_match('/[^a-zA-Z0-9_-]/', $safeKey) || in_array(strtolower($safeKey), ['yes','no','true','false','null','on','off'], true)) {
                    $safeKey = "'" . str_replace("'", "''", $safeKey) . "'";
                }
            } else {
                $safeKey = $key;
            }

            $processValue = function($val, $currentIndent) use (&$processValue) {
                $sp = str_repeat('  ', $currentIndent);

                if (is_null($val)) return 'null';
                if (is_bool($val)) return $val ? 'true' : 'false';
                if (is_numeric($val)) return (string)$val;

                if (is_string($val)) {
                    if (strpos($val, "\n") !== false) {
                        // multi-line string با indentation صحیح
                        $lines = explode("\n", $val);
                        $ml = "|\n";
                        foreach ($lines as $line) {
                            $ml .= $sp . '  ' . str_replace("\r", "", $line) . "\n";
                        }
                        return rtrim($ml);
                    }
                    return "'" . str_replace("'", "''", $val) . "'";
                }

                if (is_array($val)) {
                    if (empty($val)) return '[]';
                    $isList = array_keys($val) === range(0, count($val) - 1);
                    $nestedYaml = self::toYaml($val, $currentIndent);
                    if ($isList) {
                        $nestedLines = explode("\n", $nestedYaml);
                        return "\n" . implode("\n", array_map(function($l) use ($sp) { return $sp . "- " . ltrim($l, ' '); }, $nestedLines));
                    }
                    return "\n" . $nestedYaml;
                }

                return "'" . str_replace("'", "''", (string)$val) . "'";
            };

            if (is_array($value)) {
                if (empty($value)) {
                    $lines[] = $indentStr . $safeKey . ": []";
                    continue;
                }

                $isList = array_keys($value) === range(0, count($value) - 1);
                if ($isList) {
                    foreach ($value as $item) {
                        if (is_array($item)) {
                            $nested = self::toYaml($item, $indent + 1);
                            $nestedLines = explode("\n", $nested);
                            $lines[] = $indentStr . "- " . array_shift($nestedLines);
                            foreach ($nestedLines as $nl) {
                                $lines[] = $nl;
                            }
                        } else {
                            $lines[] = $indentStr . "- " . $processValue($item, $indent);
                        }
                    }
                } else {
                    $lines[] = $indentStr . $safeKey . ":";
                    $nested = self::toYaml($value, $indent + 1);
                    $nestedLines = explode("\n", $nested);
                    foreach ($nestedLines as $nl) {
                        $lines[] = $nl;
                    }
                }
            } else {
                $lines[] = $indentStr . $safeKey . ": " . $processValue($value, $indent);
            }
        }

        return implode("\n", $lines);
    }

    protected static function summaryString(array $res): string
    {
        if (isset($res['summary'])) {
            return $res['summary'];
        }
        return "UUID: " . ($res['input'] ?? 'unknown') . ", Valid: " . ($res['valid'] ? 'yes' : 'no');
    }

    protected static function prettyTable(array $res): string
    {
        $lines = [];
        $printValue = function ($value) use (&$printValue): string {
            if (is_array($value)) {
                $inner = [];
                foreach ($value as $k => $v) {
                    $inner[] = "{$k}=" . $printValue($v);
                }
                return implode(', ', $inner);
            }
            return (string)$value;
        };

        foreach ($res as $key => $value) {
            $lines[] = sprintf("%-25s : %s", $key, $printValue($value));
        }
        return implode(PHP_EOL, $lines);
    }

    protected static function arrayToXml(array $data, \SimpleXMLElement $xml = null): string
    {
        $xml = $xml ?: new \SimpleXMLElement('<uuid/>');
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                self::arrayToXml($value, $xml->addChild(is_numeric($key) ? "item{$key}" : $key));
            } else {
                $xml->addChild(is_numeric($key) ? "item{$key}" : $key, htmlspecialchars((string)$value));
            }
        }
        return $xml->asXML();
    }
}
