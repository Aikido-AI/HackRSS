# Redis Security Patch - Authentication Enforcement

## Summary
This patch addresses a critical security vulnerability where the SimplePie Redis cache implementation allowed unauthenticated connections to remote Redis servers.

## Changes Made

### 1. Mandatory Authentication for Remote Connections
- **Before**: Redis connections were accepted without authentication regardless of the target host
- **After**: Authentication is now **required** for all non-localhost connections
- Localhost connections (127.0.0.1, localhost, ::1) remain optional for development purposes

### 2. Enhanced Connection Security
- Added connection timeout (2.5 seconds) to prevent hanging connections
- Proper error handling with try-catch blocks for all Redis operations
- Validation of connection success before proceeding
- Clear error messages for troubleshooting

### 3. Support for Modern Redis Authentication
- **Redis 6+ ACL**: Supports username and password authentication
  - Format: `redis://username:password@host:port/dbIndex`
- **Legacy Redis**: Supports password-only authentication
  - Format: `redis://:password@host:port/dbIndex`

### 4. Default Values and Validation
- Default host: `127.0.0.1`
- Default port: `6379`
- Validates all connection parameters before use
- Prevents undefined index errors

### 5. Comprehensive Error Handling
- Connection failures throw descriptive RuntimeException
- Authentication failures are caught and reported clearly
- Database selection errors are properly handled

## Migration Guide

### For Production Deployments
If you're using Redis cache in production, you **must** update your configuration:

**Before:**
```php
$cache_location = 'redis://production-redis.example.com:6379';
```

**After (with authentication):**
```php
// For Redis 6+ with ACL
$cache_location = 'redis://myuser:mypassword@production-redis.example.com:6379';

// For legacy Redis (password only)
$cache_location = 'redis://:mypassword@production-redis.example.com:6379';
```

### For Development (Localhost)
Localhost connections continue to work without authentication:
```php
$cache_location = 'redis://localhost:6379';
$cache_location = 'redis://127.0.0.1:6379';
```

## Security Best Practices

### 1. Redis Server Configuration
Ensure your Redis server is properly secured:

```conf
# redis.conf
bind 127.0.0.1 ::1  # Only bind to localhost, or specific IPs
protected-mode yes   # Enable protected mode
requirepass your_strong_password_here  # Set a strong password

# For Redis 6+, use ACL
user default off
user myapp on >strong_password ~* &* +@all
```

### 2. Network Security
- Use firewall rules to restrict Redis port (6379) access
- Use VPN or SSH tunnels for remote Redis access
- Consider using Redis over TLS/SSL for encrypted connections
- Never expose Redis directly to the public internet

### 3. Connection Strings
- Store Redis credentials in environment variables, not in code
- Use strong, randomly generated passwords
- Rotate credentials regularly
- Use different credentials for different environments

### 4. Monitoring
- Monitor failed authentication attempts
- Set up alerts for unusual connection patterns
- Regularly audit Redis access logs

## Error Messages

### "Redis authentication is required for non-localhost connections"
**Cause**: Attempting to connect to a remote Redis server without providing credentials.
**Solution**: Add authentication to your connection URL:
```php
redis://username:password@host:port
```

### "Redis authentication failed. Please check your credentials."
**Cause**: The provided credentials are incorrect.
**Solution**: Verify your username and password are correct in the Redis server configuration.

### "Failed to connect to Redis server at host:port"
**Cause**: Cannot establish connection to the Redis server.
**Solution**: 
- Verify the Redis server is running
- Check network connectivity
- Verify firewall rules allow the connection
- Confirm the host and port are correct

## Testing

### Test Localhost Connection (No Auth)
```php
$redis = new \SimplePie\Cache\Redis('redis://localhost:6379', 'test_cache');
// Should work without authentication
```

### Test Remote Connection (Requires Auth)
```php
// This will throw an exception
$redis = new \SimplePie\Cache\Redis('redis://remote-host:6379', 'test_cache');

// This will work
$redis = new \SimplePie\Cache\Redis('redis://:password@remote-host:6379', 'test_cache');
```

## Backward Compatibility

### Breaking Changes
- **Remote connections without authentication will now fail**
  - This is intentional and addresses the security vulnerability
  - Update your configuration to include credentials

### Non-Breaking Changes
- Localhost connections continue to work as before
- Existing authenticated connections are unaffected
- All existing functionality is preserved

## References
- CVE: Unauthenticated Redis service exposed allows arbitrary remote read/write
- Redis Security Documentation: https://redis.io/docs/management/security/
- Redis ACL Documentation: https://redis.io/docs/management/security/acl/
