namespace Cirreum.Authorization.SignedRequest;

using System.Net.Http;
using System.Text.Json;

/// <summary>
/// Options for signing outbound HTTP requests (webhooks, service-to-service calls).
/// </summary>
public sealed class OutboundSigningOptions {

	/// <summary>
	/// Default signing options.
	/// </summary>
	public static OutboundSigningOptions Default { get; } = new();

	/// <summary>
	/// Default JSON serializer options using camelCase naming policy.
	/// </summary>
	public static JsonSerializerOptions DefaultJsonOptions { get; } = new() {
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase
	};

	/// <summary>
	/// Gets or sets the signature version. Default is "v1".
	/// </summary>
	public string SignatureVersion { get; set; } = "v1";

	/// <summary>
	/// Gets or sets whether to include the query string in the signature. Default is true.
	/// </summary>
	public bool IncludeQueryString { get; set; } = true;

	/// <summary>
	/// Gets or sets the header name for the client ID. Default is "X-Client-Id".
	/// </summary>
	public string ClientIdHeaderName { get; set; } = HttpRequestMessageSigningExtensions.DefaultClientIdHeader;

	/// <summary>
	/// Gets or sets the header name for the timestamp. Default is "X-Timestamp".
	/// </summary>
	public string TimestampHeaderName { get; set; } = HttpRequestMessageSigningExtensions.DefaultTimestampHeader;

	/// <summary>
	/// Gets or sets the header name for the signature. Default is "X-Signature".
	/// </summary>
	public string SignatureHeaderName { get; set; } = HttpRequestMessageSigningExtensions.DefaultSignatureHeader;

	/// <summary>
	/// Gets or sets the JSON serializer options for request bodies.
	/// If null, <see cref="DefaultJsonOptions"/> (camelCase) is used.
	/// </summary>
	public JsonSerializerOptions? JsonSerializerOptions { get; set; }
}
