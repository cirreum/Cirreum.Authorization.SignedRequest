namespace Cirreum.AuthorizationProvider.SignedRequest;

using Microsoft.AspNetCore.Authentication;

/// <summary>
/// Options for configuring signed request authentication.
/// </summary>
public sealed class SignedRequestAuthenticationOptions : AuthenticationSchemeOptions {

	/// <summary>
	/// Gets or sets the authentication scheme name.
	/// Default is "SignedRequest".
	/// </summary>
	public string SchemeName { get; set; } = "SignedRequest";
}
