namespace System.Net.Http;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cirreum.Authorization.SignedRequest;

/// <summary>
/// Extension methods for signing outbound HTTP requests with HMAC signatures.
/// Use these extensions when sending webhooks or service-to-service requests.
/// </summary>
public static class HttpRequestMessageSigningExtensions {

	/// <summary>
	/// SHA256 hash of an empty string. Used for requests without a body.
	/// </summary>
	public const string EmptyBodyHash =
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	/// <summary>
	/// Default header name for the client ID.
	/// </summary>
	public const string DefaultClientIdHeader = "X-Client-Id";

	/// <summary>
	/// Default header name for the timestamp.
	/// </summary>
	public const string DefaultTimestampHeader = "X-Timestamp";

	/// <summary>
	/// Default header name for the signature.
	/// </summary>
	public const string DefaultSignatureHeader = "X-Signature";

	/// <summary>
	/// Signs the request by adding X-Client-Id, X-Timestamp, and X-Signature headers.
	/// </summary>
	/// <param name="request">The HTTP request to sign.</param>
	/// <param name="clientId">The public client identifier.</param>
	/// <param name="signingSecret">The secret key used for HMAC signature.</param>
	/// <param name="options">Optional signing options.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>The request for chaining.</returns>
	public static async Task<HttpRequestMessage> SignRequestAsync(
		this HttpRequestMessage request,
		string clientId,
		string signingSecret,
		OutboundSigningOptions? options = null,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(request);
		ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
		ArgumentException.ThrowIfNullOrWhiteSpace(signingSecret);

		options ??= OutboundSigningOptions.Default;

		var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
		var bodyHash = await ComputeBodyHashAsync(request.Content, cancellationToken).ConfigureAwait(false);
		var path = GetRequestPath(request.RequestUri, options.IncludeQueryString);
		var method = request.Method.Method.ToUpperInvariant();

		var canonicalRequest = $"{timestamp}.{method}.{path}.{bodyHash}";
		var signature = ComputeSignature(canonicalRequest, signingSecret, options.SignatureVersion);

		request.Headers.Remove(options.ClientIdHeaderName);
		request.Headers.Remove(options.TimestampHeaderName);
		request.Headers.Remove(options.SignatureHeaderName);

		request.Headers.TryAddWithoutValidation(options.ClientIdHeaderName, clientId);
		request.Headers.TryAddWithoutValidation(options.TimestampHeaderName, timestamp.ToString());
		request.Headers.TryAddWithoutValidation(options.SignatureHeaderName, signature);

		return request;
	}

	/// <summary>
	/// Sends a signed HTTP request.
	/// </summary>
	/// <param name="client">The HTTP client.</param>
	/// <param name="request">The request to sign and send.</param>
	/// <param name="clientId">The public client identifier.</param>
	/// <param name="signingSecret">The secret key used for HMAC signature.</param>
	/// <param name="options">Optional signing options.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>The HTTP response.</returns>
	public static async Task<HttpResponseMessage> SendSignedAsync(
		this HttpClient client,
		HttpRequestMessage request,
		string clientId,
		string signingSecret,
		OutboundSigningOptions? options = null,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(client);

		await request.SignRequestAsync(clientId, signingSecret, options, cancellationToken).ConfigureAwait(false);
		return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
	}

	/// <summary>
	/// Sends a signed HTTP request with JSON content.
	/// </summary>
	/// <typeparam name="TContent">The type of the request body.</typeparam>
	/// <param name="client">The HTTP client.</param>
	/// <param name="method">The HTTP method.</param>
	/// <param name="requestUri">The request URI.</param>
	/// <param name="clientId">The public client identifier.</param>
	/// <param name="signingSecret">The secret key used for HMAC signature.</param>
	/// <param name="content">The request body (will be serialized to JSON).</param>
	/// <param name="options">Optional signing options.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>The HTTP response.</returns>
	public static Task<HttpResponseMessage> SendSignedAsync<TContent>(
		this HttpClient client,
		HttpMethod method,
		string requestUri,
		string clientId,
		string signingSecret,
		TContent? content = default,
		OutboundSigningOptions? options = null,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(client);

		var request = new HttpRequestMessage(method, requestUri);

		if (content is not null) {
			var json = JsonSerializer.Serialize(content, options?.JsonSerializerOptions ?? OutboundSigningOptions.DefaultJsonOptions);
			request.Content = new StringContent(json, Encoding.UTF8, "application/json");
		}

		return client.SendSignedAsync(request, clientId, signingSecret, options, cancellationToken);
	}

	private static async Task<string> ComputeBodyHashAsync(HttpContent? content, CancellationToken cancellationToken) {
		if (content is null) {
			return EmptyBodyHash;
		}

		var bytes = await content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

		if (bytes.Length == 0) {
			return EmptyBodyHash;
		}

		Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
		SHA256.HashData(bytes, hash);
		return Convert.ToHexString(hash).ToLowerInvariant();
	}

	private static string GetRequestPath(Uri? uri, bool includeQueryString) {
		if (uri is null) {
			return "/";
		}

		string path;
		string query;

		if (uri.IsAbsoluteUri) {
			path = uri.AbsolutePath;
			query = uri.Query;
		} else {
			var originalString = uri.OriginalString;
			var queryIndex = originalString.IndexOf('?');
			if (queryIndex >= 0) {
				path = originalString[..queryIndex];
				query = originalString[queryIndex..];
			} else {
				path = originalString;
				query = string.Empty;
			}
		}

		if (string.IsNullOrEmpty(path)) {
			path = "/";
		}

		if (includeQueryString && !string.IsNullOrEmpty(query)) {
			path += query;
		}

		return path;
	}

	private static string ComputeSignature(string canonicalRequest, string signingSecret, string version) {
		var keyBytes = Encoding.UTF8.GetBytes(signingSecret);
		var messageBytes = Encoding.UTF8.GetBytes(canonicalRequest);

		Span<byte> hmac = stackalloc byte[HMACSHA256.HashSizeInBytes];
		HMACSHA256.HashData(keyBytes, messageBytes, hmac);
		var signatureValue = Convert.ToHexString(hmac).ToLowerInvariant();

		return $"{version}={signatureValue}";
	}
}
