<?php

// SPDX-FileCopyrightText: 2004-2023 Ryan Parman, Sam Sneddon, Ryan McCue
// SPDX-FileCopyrightText: 2015 Jan Kozak <galvani78@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

declare(strict_types=1);

namespace SimplePie\Cache;

use Redis as NativeRedis;

/**
 * Caches data to redis
 *
 * Registered for URLs with the "redis" protocol
 *
 * For example, `redis://localhost:6379/?timeout=3600&prefix=sp_&dbIndex=0` will
 * connect to redis on `localhost` on port 6379. All tables will be
 * prefixed with `simple_primary-` and data will expire after 3600 seconds
 *
 * Security: Authentication is required for non-localhost connections.
 * Use `redis://user:password@host:port/dbIndex` for authenticated connections.
 * For Redis 6+ with ACL, provide both username and password.
 * For legacy Redis, provide only password: `redis://:password@host:port/dbIndex`
 *
 * @uses Redis
 * @deprecated since SimplePie 1.8.0, use implementation of "Psr\SimpleCache\CacheInterface" instead
 */
class Redis implements Base
{
    /**
     * Redis instance
     *
     * @var NativeRedis
     */
    protected $cache;

    /**
     * Options
     *
     * @var array<string, mixed>
     */
    protected $options;

    /**
     * Cache name
     *
     * @var string
     */
    protected $name;

    /**
     * Create a new cache object
     *
     * @param string $location Location string (from SimplePie::$cache_location)
     * @param string $name Unique ID for the cache
     * @param Base::TYPE_FEED|Base::TYPE_IMAGE|array<string, mixed>|null $options Either TYPE_FEED for SimplePie data, or TYPE_IMAGE for image data
     * @throws \RuntimeException If Redis connection fails or authentication is missing
     */
    public function __construct(string $location, string $name, $options = null)
    {
        //$this->cache = \flow\simple\cache\Redis::getRedisClientInstance();
        $parsed = \SimplePie\Cache::parse_URL($location);
        
        // Set default values for connection parameters
        $host = $parsed['host'] ?? '127.0.0.1';
        $port = isset($parsed['port']) ? (int)$parsed['port'] : 6379;
        $timeout = 2.5; // Connection timeout in seconds
        
        // Security: Require authentication for non-localhost connections
        // For localhost/127.0.0.1, authentication is optional (development mode)
        $isLocalhost = in_array($host, ['localhost', '127.0.0.1', '::1'], true);
        
        if (!$isLocalhost && !isset($parsed['pass'])) {
            throw new \RuntimeException(
                'Redis authentication is required for non-localhost connections. ' .
                'Please provide credentials in the connection URL: redis://user:password@host:port'
            );
        }
        
        $redis = new NativeRedis();
        
        // Attempt to connect with timeout
        try {
            $connected = $redis->connect($host, $port, $timeout);
            if (!$connected) {
                throw new \RuntimeException("Failed to connect to Redis server at {$host}:{$port}");
            }
        } catch (\RedisException $e) {
            throw new \RuntimeException("Redis connection error: " . $e->getMessage(), 0, $e);
        }
        
        // Authenticate if password is provided
        if (isset($parsed['pass'])) {
            try {
                // Support both user:pass and pass-only authentication
                if (isset($parsed['user']) && $parsed['user'] !== '') {
                    // Redis 6+ ACL authentication with username
                    $authenticated = $redis->auth([$parsed['user'], $parsed['pass']]);
                } else {
                    // Legacy password-only authentication
                    $authenticated = $redis->auth($parsed['pass']);
                }
                
                if (!$authenticated) {
                    throw new \RuntimeException('Redis authentication failed. Please check your credentials.');
                }
            } catch (\RedisException $e) {
                throw new \RuntimeException("Redis authentication error: " . $e->getMessage(), 0, $e);
            }
        }
        
        // Select database if specified in path
        if (isset($parsed['path']) && $parsed['path'] !== '' && $parsed['path'] !== '/') {
            $dbIndex = (int)substr($parsed['path'], 1);
            try {
                $selected = $redis->select($dbIndex);
                if (!$selected) {
                    throw new \RuntimeException("Failed to select Redis database {$dbIndex}");
                }
            } catch (\RedisException $e) {
                throw new \RuntimeException("Redis database selection error: " . $e->getMessage(), 0, $e);
            }
        }
        
        $this->cache = $redis;

        if (!is_null($options) && is_array($options)) {
            $this->options = $options;
        } else {
            $this->options = [
                'prefix' => 'rss:simple_primary:',
                'expire' => 0,
            ];
        }

        $this->name = $this->options['prefix'] . $name;
    }

    /**
     * @param NativeRedis $cache
     * @return void
     */
    public function setRedisClient(NativeRedis $cache)
    {
        $this->cache = $cache;
    }

    /**
     * Save data to the cache
     *
     * @param array<mixed>|\SimplePie\SimplePie $data Data to store in the cache. If passed a SimplePie object, only cache the $data property
     * @return bool Successfulness
     */
    public function save($data)
    {
        if ($data instanceof \SimplePie\SimplePie) {
            $data = $data->data;
        }
        $response = $this->cache->set($this->name, serialize($data));
        if ($this->options['expire']) {
            $this->cache->expire($this->name, $this->options['expire']);
        }

        return $response;
    }

    /**
     * Retrieve the data saved to the cache
     *
     * @return array<mixed>|false Data for SimplePie::$data
     */
    public function load()
    {
        $data = $this->cache->get($this->name);

        if ($data !== false) {
            return unserialize($data);
        }
        return false;
    }

    /**
     * Retrieve the last modified time for the cache
     *
     * @return int|false Timestamp
     */
    public function mtime()
    {
        $data = $this->cache->get($this->name);

        if ($data !== false) {
            return time();
        }

        return false;
    }

    /**
     * Set the last modified time to the current time
     *
     * @return bool Success status
     */
    public function touch()
    {
        $data = $this->cache->get($this->name);

        if ($data !== false) {
            $return = $this->cache->set($this->name, $data);
            if ($this->options['expire']) {
                return $this->cache->expire($this->name, $this->options['expire']);
            }
            return $return;
        }

        return false;
    }

    /**
     * Remove the cache
     *
     * @return bool Success status
     */
    public function unlink()
    {
        return $this->cache->set($this->name, null);
    }
}

class_alias('SimplePie\Cache\Redis', 'SimplePie_Cache_Redis');
