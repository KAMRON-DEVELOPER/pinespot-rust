use oauth2::{
    AuthUrl, ClientId, ClientSecret, RedirectUrl, RevocationUrl, TokenUrl, basic::BasicClient,
};
use serde::Deserialize;

use crate::utilities::config::Config;

#[derive(Deserialize)]
pub struct OAuthResponse {
    pub access_token: String,
    pub id_token: String,
}

#[derive(Deserialize)]
pub struct GoogleUserResult {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
    pub picture: String,
    pub locale: String,
}

pub type GoogleOAuthClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
    oauth2::EndpointSet,
>;

pub fn build_google_oauth_url(config: &Config) -> GoogleOAuthClient {
    let google_client_id =
        ClientId::new(config.google_oauth_client_id.as_ref().unwrap().to_owned());
    let google_client_secret = ClientSecret::new(
        config
            .google_oauth_client_secret
            .as_ref()
            .unwrap()
            .to_owned(),
    );
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    let redirect_uri = RedirectUrl::new(
        config
            .google_oauth_redirect_url
            .as_ref()
            .unwrap()
            .to_owned(),
    )
    .expect("Invalid redirect URL");
    let revocation_url = RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
        .expect("Invalid revocation endpoint URL");

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    BasicClient::new(google_client_id)
        .set_client_secret(google_client_secret)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_uri)
        .set_revocation_url(revocation_url)
}
