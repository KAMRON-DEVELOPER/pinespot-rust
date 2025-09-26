use oauth2::basic::{BasicErrorResponseType, BasicTokenType};
use oauth2::{
    EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    RevocationErrorResponseType, StandardErrorResponse, StandardRevocableToken,
    StandardTokenIntrospectionResponse, StandardTokenResponse,
};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreClient, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
};
use openidconnect::{Client, EmptyAdditionalClaims, IdTokenFields, reqwest};
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};

use crate::utilities::config::Config;
use crate::utilities::errors::AppError;

pub type GoogleOAuthOpenIdConnectClient = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<
        IdTokenFields<
            EmptyAdditionalClaims,
            EmptyExtraTokenFields,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >,
        BasicTokenType,
    >,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub async fn build_google_oauth_openidconnect_client(
    config: &Config,
) -> Result<GoogleOAuthOpenIdConnectClient, AppError> {
    let issuer_url = IssuerUrl::new("https://accounts.google.com".to_string())?;

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // Use OpenID Connect Discovery to fetch the provider metadata asynchronously.
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;

    let google_client_id =
        ClientId::new(config.google_oauth_client_id.as_ref().unwrap().to_owned());
    let google_client_secret = ClientSecret::new(
        config
            .google_oauth_client_secret
            .as_ref()
            .unwrap()
            .to_owned(),
    );

    let redirect_uri = RedirectUrl::new(
        config
            .google_oauth_redirect_url
            .as_ref()
            .unwrap()
            .to_owned(),
    )?;

    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        google_client_id,
        Some(google_client_secret),
    )
    .set_redirect_uri(redirect_uri);

    Ok(client)
}
