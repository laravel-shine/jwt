# Simple-PHP-JWT

Simple JSON Web Token for PHP

## Requirements

* PHP > 7.0
* OpenSSL

## Capabilities

Function | Algorithm
-|-
✅ Sign | ✅ HS256
✅ Verify | ✅ HS384
❎ `iss` check | ✅ HS512
❎ `sub` check | ✅ RS256
❎ `aud` check | ✅ RS384
❎ `exp` check | ✅ RS512
❎ `nbf` check |
❎ `iat` check |
❎ `jti` check |

## Basic Usage

### encode(array payload, string $key, string $algorithm)

```php
try {
    $token = JWT::encode(['sub' => '1234567890', 'name' => 'John Smith'], $key256bit, 'HS256');
} catch (\Exception $e) {
    // encode error
}
```

### decode(string $token, string $key)

```php
try {
    $payload = JWT::decode($token, $key256bit);
    // $payload->sub == '1234567890'
} catch (\Exception $e) {
    // $e->getCode()
}
```

## Exceptions

### decode()
Code | Reason
-|-
1 | Invalid token format
2 | Invalid header encoding
3 | Invalid token header
4 | Algorithm not supported
5 | Invalid payload encoding
6 | Invalid signature
