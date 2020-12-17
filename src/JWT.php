<?php

namespace LaravelShine\JWT;

class JWT
{
    protected static $algs = [
        'HS256' => 'SHA256',
        'HS384' => 'SHA384',
        'HS512' => 'SHA512',
        'RS256' => 'SHA256',
        'RS384' => 'SHA384',
        'RS512' => 'SHA512',
    ];

    public static function supportedAlg(string $alg = null)
    {
        return $alg ? isset(static::$algs[$alg]) : array_keys(static::$algs);
    }

    public static function encode(array $payload, $key, string $alg = 'HS256'): string
    {
        if (!static::supportedAlg($alg)) {
            throw new \DomainException('Algorithm not supported');
        }

        $header = static::jsonBase64Encode(['alg' => $alg, 'typ' => 'JWT']);
        $payload = static::jsonBase64Encode($payload);
        $signature = static::sign($header.'.'.$payload, $key, $alg);

        return $header.'.'.$payload.'.'.$signature;
    }

    public static function decode(string $token, $key)
    {
        $token = explode('.', $token);

        if (count($token) != 3) {
            throw new \InvalidArgumentException('Invalid token segments', 1);
        }

        if (!$header = static::jsonBase64Decode($token[0])) {
            throw new \InvalidArgumentException('Invalid header encoding', 2);
        }

        if (empty($header->alg) || empty($header->typ) || $header->typ !== 'JWT') {
            throw new \UnexpectedValueException('Invalid header', 3);
        }

        if (!static::supportedAlg($header->alg)) {
            throw new \DomainException('Algorithm not supported', 4);
        }

        if (!$payload = static::jsonBase64Decode($token[1])) {
            throw new \InvalidArgumentException('Invalid payload encoding', 5);
        }

        if (!static::verify($token[0].'.'.$token[1], $token[2], $key, $header->alg)) {
            throw new \UnexpectedValueException('Invalid signature', 6);
        }

        return $payload;
    }

    public static function sign(string $msg, $key, string $alg): string
    {
        switch ($alg = strtoupper($alg)) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                $sign = hash_hmac(static::$algs[$alg], $msg, $key, true);

                break;
            case 'RS256':
            case 'RS384':
            case 'RS512':
                if (!openssl_sign($msg, $sign, $key, static::$algs[$alg])) {
                    throw new \RuntimeException('Signature fail');
                }

                break;
            default:
                throw new \DomainException('Algorithm not supported');
        }

        return static::base64UrlEncode($sign);
    }

    public static function verify(string $msg, string $sign, $key, string $alg): bool
    {
        switch ($alg = strtoupper($alg)) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return hash_equals(static::sign($msg, $key, $alg), $sign);
            case 'RS256':
            case 'RS384':
            case 'RS512':
                return openssl_verify($msg, static::base64UrlDecode($sign), $key, static::$algs[$alg]) === 1;
            default:
                throw new \DomainException('Algorithm not supported');
        }
    }

    public static function base64UrlEncode(string $string)
    {
        return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $string)
    {
        return base64_decode(strtr($string, '-_', '+/').substr('===', (strlen($string) + 3) % 4), true);
    }

    public static function jsonDecode(string $string, bool $toarray = false)
    {
        return json_decode($string, $toarray, 512, JSON_BIGINT_AS_STRING);
    }

    public static function jsonEncode($data)
    {
        return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public static function jsonBase64Decode(string $string, bool $toarray = false)
    {
        return static::jsonDecode(static::base64UrlDecode($string), $toarray);
    }

    public static function jsonBase64Encode($data)
    {
        return static::base64UrlEncode(static::jsonEncode($data));
    }
}
