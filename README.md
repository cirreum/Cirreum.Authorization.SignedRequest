# Cirreum Authorization Provider - Signed Request

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authorization.SignedRequest.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authorization.SignedRequest/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Authorization.SignedRequest.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authorization.SignedRequest/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Authorization.SignedRequest?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Authorization.SignedRequest/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Authorization.SignedRequest?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Authorization.SignedRequest/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**HMAC signed request authentication for the Cirreum Framework**

## Overview

**Cirreum.Authorization.SignedRequest** provides bank-grade HMAC signature authentication for ASP.NET Core applications. Designed for high-security scenarios like financial APIs, external partner integrations, and ISO/PCI compliance requirements where simple API keys are insufficient.

### Key Features

- **HMAC-SHA256 signatures** - Cryptographically signed requests prevent tampering
- **Replay protection** - Timestamp validation rejects stale requests (default 2 minutes)
- **Signature versioning** - Future-proof with `v1=` prefix for algorithm upgrades
- **Key rotation** - Support multiple active signing credentials per client
- **Per-client options** - Override timestamp tolerance and signature versions per client
- **Rate limiting hooks** - `ISignatureValidationEvents` interface for custom rate limiting
- **Efficient lookup** - Direct database query by `X-Client-Id` header
- **Constant-time comparison** - Prevents timing attacks on signature validation
- **Outbound signing** - Sign outgoing webhooks and service-to-service requests

### Use Cases

- External partner/customer API access
- Financial transaction APIs
- ISO 27001 / PCI-DSS compliance requirements
- **Sending signed webhooks** to customers
- **Receiving signed requests** from partners
- High-security service-to-service communication

### Comparison with API Keys

| Feature | API Key | Signed Request |
|---------|---------|----------------|
| Secret transmitted | Yes (in header) | No (used to sign) |
| Replay protection | No | Yes (timestamp) |
| Request tampering | Possible | Detectable |
| Key rotation | Manual | Zero-downtime |
| Compliance level | Basic | ISO/PCI ready |

## Installation

```bash
dotnet add package Cirreum.Authorization.SignedRequest
```

## Quick Start

### 1. Register in Program.cs

```csharp
builder.AddAuthorization(auth => auth
    .AddSignedRequest<DatabaseSignedRequestResolver>()
    .AddSignatureValidationEvents<RateLimitingEvents>()  // Optional
)
.AddPolicy("Partner", policy => {
    policy
        .AddAuthenticationSchemes(SignedRequestDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .RequireRole("partner");
});
```

### 2. Implement the Resolver

```csharp
public class DatabaseSignedRequestResolver : DynamicSignedRequestClientResolver {
    private readonly IDbConnection _db;

    public DatabaseSignedRequestResolver(
        ISignatureValidator validator,
        IOptions<SignatureValidationOptions> options,
        IDbConnection db,
        ILogger<DatabaseSignedRequestResolver> logger)
        : base(validator, options, logger) {
        _db = db;
    }

    protected override async Task<IEnumerable<StoredSigningCredential>> LookupCredentialsAsync(
        string clientId,
        CancellationToken cancellationToken) {

        return await _db.QueryAsync<StoredSigningCredential>("""
            SELECT
                CredentialId,
                ClientId,
                ClientName,
                SigningSecret,
                IsActive,
                ExpiresAt,
                Roles,
                Claims,
                TimestampTolerance,
                FutureTimestampTolerance,
                SupportedSignatureVersions
            FROM SigningCredentials
            WHERE ClientId = @ClientId
              AND IsActive = 1
              AND (ExpiresAt IS NULL OR ExpiresAt > @Now)
            """,
            new { ClientId = clientId, Now = DateTime.UtcNow });
    }
}
```

### 3. Protect Your Endpoints

```csharp
[ApiController]
[Route("api/[controller]")]
public class TransactionsController : ControllerBase {

    [HttpPost("transfer")]
    [Authorize(Policy = "Partner")]
    public IActionResult Transfer([FromBody] TransferRequest request) {
        // Request is authenticated and signature verified
        return Ok();
    }
}
```

## How It Works

### Request Headers

Partners include three headers with each request:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Client-Id` | Public client identifier | `partner_acme_corp` |
| `X-Timestamp` | Unix timestamp (seconds) | `1734567890` |
| `X-Signature` | HMAC signature | `v1=a1b2c3d4e5f6...` |

### Signature Computation

The signature is computed over a canonical request string:

```
{timestamp}.{method}.{path}.{bodyHash}
```

Example:
```
1734567890.POST./api/transactions/transfer.e3b0c44298fc1c149afbf4c8996fb924...
```

### Partner Implementation (Client Side)

For partners consuming your API, point them to the lightweight client SDK:

```bash
dotnet add package Cirreum.Authorization.SignedRequest.Client
```

```csharp
using System.Net.Http;

var credentials = new SigningCredentials("partner_acme_corp", "their-signing-secret");

var response = await httpClient.SendSignedAsync(
    HttpMethod.Post,
    "https://api.yourcompany.com/transactions",
    credentials,
    content: new { amount = 100.00, currency = "USD" });
```

See [Cirreum.Authorization.SignedRequest.Client](https://www.nuget.org/packages/Cirreum.Authorization.SignedRequest.Client/) for full documentation.

## Sending Signed Webhooks

When your server needs to send signed requests to customers (webhooks), use the outbound signing extensions:

```csharp
using System.Net.Http;

public class WebhookService {
    private readonly HttpClient _httpClient;
    private readonly ICustomerRepository _customers;

    public WebhookService(HttpClient httpClient, ICustomerRepository customers) {
        _httpClient = httpClient;
        _customers = customers;
    }

    public async Task SendWebhookAsync(string customerId, object payload) {
        // Look up customer's webhook configuration
        var customer = await _customers.GetAsync(customerId);

        // Sign and send the webhook
        var response = await _httpClient.SendSignedAsync(
            HttpMethod.Post,
            customer.WebhookUrl,
            customer.ClientId,
            customer.WebhookSigningSecret,
            content: payload);

        // Handle response...
    }
}
```

### Signing Options

```csharp
var options = new OutboundSigningOptions {
    SignatureVersion = "v1",
    IncludeQueryString = true,
    ClientIdHeaderName = "X-Client-Id",
    TimestampHeaderName = "X-Timestamp",
    SignatureHeaderName = "X-Signature"
};

await httpClient.SendSignedAsync(request, clientId, secret, options);
```

### Sign Without Sending

```csharp
var request = new HttpRequestMessage(HttpMethod.Post, webhookUrl);
request.Content = JsonContent.Create(payload);

// Sign the request (adds headers)
await request.SignRequestAsync(clientId, signingSecret);

// Send later or inspect headers
var response = await httpClient.SendAsync(request);
```

## Configuration

### Global Validation Options

Configure app-wide defaults at startup:

```csharp
builder.AddAuthorization(auth => auth
    .AddSignedRequest<DatabaseSignedRequestResolver>(options => options
        .ConfigureValidation(v => {
            v.TimestampTolerance = TimeSpan.FromMinutes(2);      // Max request age
            v.FutureTimestampTolerance = TimeSpan.FromSeconds(30); // Clock skew allowance
            v.IncludeQueryString = true;                          // Include query in signature
            v.ClientIdHeaderName = "X-Client-Id";                 // Customizable headers
            v.SignatureHeaderName = "X-Signature";
            v.TimestampHeaderName = "X-Timestamp";
        }))
);
```

### Per-Client Overrides

Override specific settings per client via `StoredSigningCredential` properties:

| Property | Description | Use Case |
|----------|-------------|----------|
| `TimestampTolerance` | Max request age for this client | Clients with clock skew issues |
| `FutureTimestampTolerance` | Future timestamp allowance | Clients with clocks running ahead |
| `SupportedSignatureVersions` | Allowed signature versions | Restrict legacy clients to v1, allow v2 for new clients |

When null, the global app defaults are used. This enables fine-grained control without affecting other clients:

```csharp
// In your resolver, return credentials with per-client overrides
new StoredSigningCredential {
    CredentialId = "cred_123",
    ClientId = "partner_legacy",
    ClientName = "Legacy Partner",
    SigningSecret = "...",
    // Allow 5 minutes for this client with known clock issues
    TimestampTolerance = TimeSpan.FromMinutes(5),
    // Restrict to v1 only
    SupportedSignatureVersions = new HashSet<string> { "v1" }
};
```

### Rate Limiting Events

Implement `ISignatureValidationEvents` for custom rate limiting:

```csharp
public class RateLimitingEvents : ISignatureValidationEvents {
    private readonly IDistributedCache _cache;

    public RateLimitingEvents(IDistributedCache cache) {
        _cache = cache;
    }

    public async Task OnValidationFailedAsync(
        SignatureValidationFailedContext context,
        CancellationToken cancellationToken) {

        if (context.ClientId is null) return;

        var key = $"auth:failures:{context.ClientId}";
        var failures = await _cache.GetAsync(key, cancellationToken);
        var count = failures is null ? 1 : BitConverter.ToInt32(failures) + 1;

        await _cache.SetAsync(key, BitConverter.GetBytes(count),
            new DistributedCacheEntryOptions {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15)
            }, cancellationToken);
    }

    public Task OnValidationSucceededAsync(
        SignatureValidationSucceededContext context,
        CancellationToken cancellationToken) {

        var key = $"auth:failures:{context.Client.ClientId}";
        return _cache.RemoveAsync(key, cancellationToken);
    }

    public async Task<bool> IsClientBlockedAsync(
        string clientId,
        CancellationToken cancellationToken) {

        var key = $"auth:failures:{clientId}";
        var failures = await _cache.GetAsync(key, cancellationToken);
        return failures is not null && BitConverter.ToInt32(failures) >= 5;
    }
}
```

## Key Rotation

Support zero-downtime key rotation by maintaining multiple active credentials:

```sql
-- Add new credential (both old and new are active)
INSERT INTO SigningCredentials (CredentialId, ClientId, SigningSecret, IsActive, ExpiresAt)
VALUES ('cred_v2', 'partner_acme', 'new-secret', 1, NULL);

-- Partners switch to new credential

-- Deactivate old credential
UPDATE SigningCredentials SET IsActive = 0 WHERE CredentialId = 'cred_v1';
```

The resolver tries all active credentials, so partners can migrate at their own pace.

## Database Schema

Example schema for storing signing credentials:

```sql
CREATE TABLE SigningCredentials (
    CredentialId NVARCHAR(50) PRIMARY KEY,
    ClientId NVARCHAR(100) NOT NULL,
    ClientName NVARCHAR(200) NOT NULL,
    SigningSecret NVARCHAR(500) NOT NULL,  -- Encrypted at rest
    IsActive BIT NOT NULL DEFAULT 1,
    ExpiresAt DATETIME2 NULL,
    Roles NVARCHAR(MAX) NULL,              -- JSON array
    Claims NVARCHAR(MAX) NULL,             -- JSON object
    TimestampTolerance INT NULL,           -- Seconds, per-client override
    FutureTimestampTolerance INT NULL,     -- Seconds, per-client override
    SupportedSignatureVersions NVARCHAR(MAX) NULL, -- JSON array, e.g. ["v1", "v2"]
    CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),

    INDEX IX_SigningCredentials_ClientId (ClientId)
);
```

## Security Considerations

- **Secret storage** - Store signing secrets encrypted at rest in your database
- **Secret rotation** - Rotate secrets regularly; the multi-credential support enables zero-downtime rotation
- **Timestamp validation** - The 2-minute default provides replay protection while allowing for network latency
- **Constant-time comparison** - Signature validation uses `CryptographicOperations.FixedTimeEquals`
- **Rate limiting** - Implement `ISignatureValidationEvents` to block brute-force attempts
- **Transport security** - Always use HTTPS

## Claims

Authenticated requests receive the following claims:

| Claim | Value |
|-------|-------|
| `ClaimTypes.NameIdentifier` | ClientId |
| `ClaimTypes.Name` | ClientName |
| `ClaimTypes.Role` | Each configured role |
| `client_type` | `signed_request` |
| `auth_scheme` | `SignedRequest` |
| `credential_id` | The matched credential ID |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
