<?php
namespace ArashAnvari\UuidInspector\Tests;

use PHPUnit\Framework\TestCase;
use ArashAnvari\UuidInspector\UuidInspector;

class UuidInspectorTest extends TestCase
{
    public function testParseValidV1(): void
    {
        $uuid = 'b3f9d78b-bdda-11ef-a506-0255ac120164';
        $result = UuidInspector::parse($uuid);

        $this->assertIsArray($result);
        $this->assertTrue($result['valid']);
        $this->assertEquals(1, $result['version']);
        $this->assertEquals('RFC 4122 (10x)', $result['variant']);
        $this->assertNotEmpty($result['detail']['v1']);
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}/', $result['detail']['v1']['datetime_utc']);
    }

    public function testParseV4(): void
    {
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        $result = UuidInspector::parse($uuid);

        $this->assertIsArray($result);
        $this->assertTrue($result['valid']);
        $this->assertEquals(4, $result['version']);
        $this->assertEquals('RFC 4122 (10x)', $result['variant']);
        $this->assertArrayHasKey('detail', $result);
        $this->assertArrayHasKey('v4', $result['detail']);
    }

    public function testParseWithoutDashes(): void
    {
        $uuid = '550e8400e29b41d4a716446655440000';
        $result = UuidInspector::parse($uuid);

        $this->assertTrue($result['valid']);
        $this->assertEquals('550e8400-e29b-41d4-a716-446655440000', $result['normalized']);
    }

    public function testNilUuid(): void
    {
        $uuid = '00000000-0000-0000-0000-000000000000';
        $result = UuidInspector::parse($uuid);

        $this->assertTrue($result['is_nil']);
        $this->assertStringContainsString('Nil UUID', implode(' ', $result['notes']));
    }

    public function testMaxUuid(): void
    {
        $uuid = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
        $result = UuidInspector::parse($uuid);

        $this->assertTrue($result['is_max']);
        $this->assertStringContainsStringIgnoringCase(
            'all-ones UUID',
            implode(' ', $result['notes']),
            'Notes should mention all-ones UUID'
        );
    }

    public function testParseInvalidUuid(): void
    {
        $uuid = 'invalid-uuid-string';
        $result = UuidInspector::parse($uuid);

        $this->assertFalse($result['valid']);
        $this->assertStringContainsString('Invalid UUID format', implode(' ', $result['notes']));
    }

    public function testIsValid(): void
    {
        $validUuid = '550e8400-e29b-41d4-a716-446655440000';
        $invalidUuid = '00000000-0000-0000-0000-000000000000';
        $malformedUuid = 'invaliduuid';

        $this->assertTrue(UuidInspector::isValid($validUuid));
        $this->assertFalse(UuidInspector::isValid($invalidUuid));
        $this->assertFalse(UuidInspector::isValid($malformedUuid));
    }

    public function testVersion(): void
    {
        $this->assertEquals(4, UuidInspector::version('550e8400-e29b-41d4-a716-446655440000'));
        $this->assertEquals(1, UuidInspector::version('b3f9d78b-bdda-11ef-a506-0255ac120164'));
        $this->assertNull(UuidInspector::version('invaliduuid'));
    }

    public function testVariant(): void
    {
        $this->assertEquals('RFC 4122 (Leach–Salz)', UuidInspector::variant('550e8400-e29b-41d4-a716-446655440000'));
        $this->assertNull(UuidInspector::variant('invaliduuid'));
    }

    public function testAnalyze(): void
    {
        $uuid = 'b3f9d78b-bdda-11ef-a506-0255ac120164';
        $result = UuidInspector::analyze($uuid);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('valid', $result);
        $this->assertArrayHasKey('version', $result);
        $this->assertArrayHasKey('variant', $result);
        $this->assertArrayHasKey('timestamp', $result);
        $this->assertArrayHasKey('mac_address', $result);
        $this->assertEquals(1, $result['version']);
        $this->assertEquals('RFC 4122 (Leach–Salz)', $result['variant']);
    }

    public function testParseJsonFormat(): void
    {
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        $json = UuidInspector::parse($uuid, 'json');

        $this->assertNotEmpty($json, "JSON output should not be empty");
    }

    public function testParseStringFormat(): void
    {
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        $string = UuidInspector::parse($uuid, 'string');

        $this->assertIsString($string);
        $this->assertStringContainsString('UUID 550e8400-e29b-41d4-a716-446655440000', $string);
    }
}
