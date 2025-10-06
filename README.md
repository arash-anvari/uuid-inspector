# UUID Inspector

* A Laravel package to parse and extract detailed information from UUIDs (v1-v5).
* It provides validation, normalization, variant detection, and detailed data extraction for all UUID versions. Fully compatible with Laravel 10+.

## Installation & Configuration & Usage
```bash
# Install the package via Composer
composer require arash-anvari/uuid-inspector
```

## Publish the configuration file (optional)
```bash
php artisan vendor:publish --provider="ArashAnvari\UuidInspector\UuidInspectorServiceProvider" --tag="config"
```

* The configuration file is located at config/uuid-inspector.php

* Customize default options such as output format, validation strictness, and timestamp formatting

## Usage via Facade
```
use UuidInspector;

$uuid = '550e8400-e29b-41d4-a716-446655440000';
```

## Validate UUID
```
$isValid = UuidInspector::validate($uuid);
```

## Get UUID version
```
$version = UuidInspector::version($uuid);
```

## Extract detailed information
```
$details = UuidInspector::inspect($uuid);
```

## Usage via Dependency Injection
```
use ArashAnvari\UuidInspector\UuidInspectorService;

public function __construct(private UuidInspectorService $uuidInspector) {}

public function show($uuid)
{
    $isValid = $this->uuidInspector->validate($uuid);
    $details = $this->uuidInspector->inspect($uuid);
}
```

## Options
## Options

* **format**: Set output format (array, json, object)  
* **strict_validation**: Enable or disable strict UUID validation  
* **timestamp_format**: Customize date/time format for v1 UUIDs


## Features
* Supports UUID versions 1 through 5
* Validation and normalization
* Variant detection (RFC 4122 and others)
* Detailed information extraction: timestamp (v1), node & clock sequence (v1), namespace & name (v3/v5)
* Works seamlessly with Laravel 10+

## UUID Version Details
* v1: Time-based, includes timestamp, clock sequence, and node (MAC address)
* v2: DCE Security version (less commonly used)
* v3: Name-based (MD5 hashing)
* v4: Randomly generated
* v5: Name-based (SHA1 hashing)

## Testing
```bash
vendor/bin/phpunit
```

## License
#### MIT License
