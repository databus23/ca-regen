# CA Regeneration Test

This Go program demonstrates CA regeneration with modified basic constraints and validates that it breaks backward compatibility with existing clients.

## Purpose

The program validates that regenerating a CA certificate with critical basic constraints creates incompatibility with clients that have the original CA certificate. This is useful for testing CA migration scenarios where you want to understand the impact of CA regeneration on existing client connections.

## How it works

1. **Loads** the original CA certificate and private key from PEM files
2. **Generates** a new CA certificate with identical properties except for critical basic constraints
3. **Saves** the new CA certificate to `new-ca.pem` for inspection
4. **Creates** a server certificate signed by the new CA for "localhost"
5. **Starts** a web server using the new server certificate
6. **Tests** client compatibility with both the original CA and new CA

## Usage

```bash
go run main.go -ca-cert <path-to-ca-cert.pem> -ca-key <path-to-ca-key.pem>
```

## Example

```bash
# Generate a test CA first (optional)
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem -days 365 -nodes -subj "/CN=Test CA"

# Run the program
go run main.go -ca-cert ca-cert.pem -ca-key ca-key.pem
```

## Expected Output

The program will demonstrate that CA regeneration breaks backward compatibility:

```
✓ Loaded original CA certificate and key
✓ Verified: Basic constraints are critical in the new CA
✓ Generated new CA with critical basic constraints
✓ Saved new CA to new-ca.pem for inspection
✓ Generated server certificate for localhost
✓ Web server started on https://localhost:8443

=== Testing CA Compatibility ===

Test 1: Client with original CA
❌ Expected failure with original CA: client request failed: Get "https://localhost:8443": tls: failed to verify certificate: x509: certificate signed by unknown authority

Test 2: Client with new CA
✓ Client received response: Hello from regenerated CA server!

🎉 Success! The regenerated CA with critical basic constraints is NOT compatible with clients using the original CA.
This demonstrates that changing basic constraints to critical breaks backward compatibility.
```

## Key Features

- **Single file**: Everything is contained in `main.go`
- **PEM support**: Accepts standard PEM-encoded certificates and keys (PKCS#1 and PKCS#8)
- **Real validation**: Actually starts a web server and makes HTTPS requests
- **Clear output**: Provides step-by-step feedback on the process
- **Error handling**: Comprehensive error checking and reporting
- **CA inspection**: Saves the new CA certificate to `new-ca.pem` for detailed examination
- **Dual testing**: Tests compatibility with both original and new CA certificates

## Technical Details

The program demonstrates that:
- CA certificates can be regenerated with critical basic constraints
- The regenerated CA is functionally different from the original CA
- Server certificates issued by the new CA are NOT trusted by clients with the original CA
- Server certificates issued by the new CA ARE trusted by clients with the new CA
- Changing basic constraints to critical breaks backward compatibility
- CA regeneration creates incompatibility even with identical keys and most properties

## Files Generated

- `new-ca.pem`: The regenerated CA certificate with critical basic constraints for inspection
