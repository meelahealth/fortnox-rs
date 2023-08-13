#[macro_use]
extern crate serde_derive;

mod http;

pub mod id;

use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use http::apis::configuration::{self, Configuration};
use http::apis::customers_resource_api::{
    CreateCustomersResourceError, CreateCustomersResourceParams, GetCustomersResourceError,
    GetCustomersResourceParams, UpdateCustomersResourceError, UpdateCustomersResourceParams,
};
use http::apis::invoices_resource_api::{
    BookkeepInvoicesResourceError, BookkeepInvoicesResourceParams, CreateInvoicesResourceError,
    CreateInvoicesResourceParams, CreditError, CreditParams, EmailError, EmailParams,
    GetInvoicesResourceError, GetInvoicesResourceParams, ListInvoicesResourceError,
    ListInvoicesResourceParams, PrintError, PrintParams,
};
use http::models::{
    document_reference, Customer, CustomerWrap, Invoice, InvoiceListItem, InvoicePayload,
    InvoicePayloadInvoiceRow, InvoicePayloadWrap,
};
use id::CustomerId;
use oauth2::basic::{BasicClient, BasicErrorResponseType, BasicTokenType};
use oauth2::reqwest::async_http_client;
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, RedirectUrl, RefreshToken, RequestTokenError, Scope as OAuth2Scope,
    StandardErrorResponse, StandardTokenResponse, TokenResponse as _, TokenUrl,
};
use reqwest::header;
use rust_decimal::Decimal;
use tokio::sync::RwLock;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    CompanyInfo,
    Invoice,
    Customer,
}

impl Scope {
    pub const fn all() -> &'static [Scope] {
        &[Scope::CompanyInfo, Scope::Invoice, Scope::Customer]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::CompanyInfo => "companyinformation",
            Scope::Invoice => "invoice",
            Scope::Customer => "customer",
        }
    }
}

impl From<Scope> for OAuth2Scope {
    fn from(value: Scope) -> Self {
        OAuth2Scope::new(value.as_str().to_string())
    }
}

type TokenResponse = StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>;
type TokenError = RequestTokenError<
    oauth2::reqwest::Error<reqwest::Error>,
    StandardErrorResponse<BasicErrorResponseType>,
>;

pub struct OAuthClient(BasicClient);

impl OAuthClient {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: Url) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
            AuthUrl::new("https://apps.fortnox.se/oauth-v1/auth".to_string()).unwrap(),
            Some(TokenUrl::new("https://apps.fortnox.se/oauth-v1/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url.to_string()).unwrap())
        .set_auth_type(oauth2::AuthType::BasicAuth);

        Self(client)
    }

    pub fn authenticate(&self, scopes: &[Scope]) -> (Url, CsrfToken) {
        let mut client = self
            .0
            .authorize_url(CsrfToken::new_random)
            .add_extra_param("access_type", "offline")
            .add_extra_param("account_type", "service");

        for scope in scopes.iter().copied() {
            client = client.add_scope(scope.into());
        }

        client.url()
    }

    pub async fn exchange_code(&self, code: &str) -> Result<TokenResponse, TokenError> {
        let token_result = self
            .0
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await?;

        Ok(token_result)
    }

    pub async fn exchange_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<TokenResponse, TokenError> {
        let result = self
            .0
            .exchange_refresh_token(&refresh_token)
            .request_async(async_http_client)
            .await?;
        Ok(result)
    }
}

pub struct Client {
    oauth_client: OAuthClient,
    config: RwLock<Configuration>,
    creds: RwLock<OAuthCredentials>,
}

fn make_http_client(access_token: &AccessToken) -> reqwest::Client {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        "Authorization",
        header::HeaderValue::from_str(&format!("Bearer {}", access_token.secret())).unwrap(),
    );

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

impl Client {
    async fn check_bearer_token(&self) -> Result<(), TokenError> {
        // If the configuration is locked, it means the tokens are being refreshed right now.
        let current_refresh_token = {
            let creds = self.creds.read().await;

            let Some(expires_at) = creds.expires_at.as_ref() else {
                return Ok(());
            };

            if &Utc::now() < expires_at {
                return Ok(());
            }

            if let Some(refresh_token) = creds.refresh_token.clone() {
                refresh_token
            } else {
                return Ok(());
            }
        };

        let mut creds = self.creds.write().await;

        // It was updated by another task.
        let Some(refresh_token) = creds.refresh_token.take() else {
            return Ok(());
        };

        if current_refresh_token.secret() != refresh_token.secret() {
            return Ok(());
        }

        // We're the responsible task. Time to refresh.
        let res = self
            .oauth_client
            .exchange_refresh_token(&refresh_token)
            .await?;

        self.config.write().await.client = make_http_client(res.access_token());

        creds.access_token = res.access_token().clone();
        creds.refresh_token = res.refresh_token().cloned();
        creds.expires_at = res
            .expires_in()
            .map(|x| chrono::Duration::seconds(x.as_secs() as i64 - 90))
            .map(|x| Utc::now() + x);

        creds.save().unwrap();

        Ok(())
    }

    pub fn new(oauth_client: OAuthClient, creds: OAuthCredentials) -> Self {
        let config = Configuration {
            base_path: "https://api.fortnox.se".to_string(),
            user_agent: Some(format!("fortnox-rs/{}", env!("CARGO_PKG_VERSION"))),
            client: make_http_client(&creds.access_token),
        };

        Self {
            oauth_client,
            config: RwLock::from(config),
            creds: RwLock::from(creds),
        }
    }

    pub async fn customer<const P: char>(
        &self,
        id: CustomerId<P>,
    ) -> Result<Customer, http::apis::Error<GetCustomersResourceError>> {
        self.check_bearer_token().await?;

        let result = http::apis::customers_resource_api::get_customers_resource(
            &*self.config.read().await,
            GetCustomersResourceParams {
                customer_number: id.to_string(),
            },
        )
        .await?;

        Ok(*result.customer)
    }

    pub async fn create_or_update_customer<const P: char>(
        &self,
        customer_id: CustomerId<P>,
        details: UpdateCustomer,
    ) -> Result<Customer, http::apis::Error<CreateCustomersResourceError>> {
        match self.update_customer(customer_id, details.clone()).await {
            Ok(v) => return Ok(v),
            Err(_e) => {}
        }

        self.create_customer(customer_id, details).await
    }

    pub async fn create_customer<const P: char>(
        &self,
        customer_id: CustomerId<P>,
        details: UpdateCustomer,
    ) -> Result<Customer, http::apis::Error<CreateCustomersResourceError>> {
        self.check_bearer_token().await?;

        let result = http::apis::customers_resource_api::create_customers_resource(
            &*self.config.read().await,
            CreateCustomersResourceParams {
                customer: Some(CustomerWrap {
                    customer: Box::new(Customer {
                        customer_number: customer_id.to_string().into(),
                        organisation_number: details.org_nr.into(),
                        name: details.name.into(),
                        address1: details.address1.into(),
                        address2: details.address2.into(),
                        city: details.city.into(),
                        zip_code: details.post_code.into(),
                        country_code: details.country_code.into(),
                        active: details.active.into(),
                        email_invoice: details
                            .email_invoice
                            .or_else(|| details.email.clone())
                            .into(),
                        email: details.email.into(),
                        external_reference: details.external_reference.into(),
                        ..Default::default()
                    }),
                }),
            },
        )
        .await?;

        Ok(*result.customer)
    }

    pub async fn update_customer<const P: char>(
        &self,
        id: CustomerId<P>,
        details: UpdateCustomer,
    ) -> Result<Customer, http::apis::Error<UpdateCustomersResourceError>> {
        self.check_bearer_token().await?;

        let result = http::apis::customers_resource_api::update_customers_resource(
            &*self.config.read().await,
            UpdateCustomersResourceParams {
                customer_number: id.to_string(),
                customer: CustomerWrap {
                    customer: Box::new(Customer {
                        organisation_number: details.org_nr.into(),
                        name: details.name.into(),
                        address1: details.address1.into(),
                        address2: details.address2.into(),
                        city: details.city.into(),
                        zip_code: details.post_code.into(),
                        country_code: details.country_code.into(),
                        active: details.active.into(),
                        email_invoice: details
                            .email_invoice
                            .or_else(|| details.email.clone())
                            .into(),
                        email: details.email.into(),
                        external_reference: details.external_reference.into(),
                        ..Default::default()
                    }),
                },
            },
        )
        .await?;

        Ok(*result.customer)
    }

    pub async fn book_invoice(
        &self,
        invoice_id: &str,
    ) -> Result<Invoice, http::apis::Error<BookkeepInvoicesResourceError>> {
        self.check_bearer_token().await?;

        let result = http::apis::invoices_resource_api::bookkeep_invoices_resource(
            &*self.config.read().await,
            BookkeepInvoicesResourceParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?;

        Ok(*result.invoice)
    }

    pub async fn invoice(
        &self,
        invoice_id: &str,
    ) -> Result<Invoice, http::apis::Error<GetInvoicesResourceError>> {
        self.check_bearer_token().await?;

        let result = http::apis::invoices_resource_api::get_invoices_resource(
            &*self.config.read().await,
            GetInvoicesResourceParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?;

        Ok(*result.invoice)
    }

    pub async fn refund_invoice(
        &self,
        invoice_id: &str,
    ) -> Result<Invoice, http::apis::Error<CreditError>> {
        self.check_bearer_token().await?;

        let result = http::apis::invoices_resource_api::credit(
            &*self.config.read().await,
            CreditParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?;

        Ok(*result.invoice)
    }

    pub async fn download_invoice_pdf(
        &self,
        invoice_id: &str,
    ) -> Result<Vec<u8>, http::apis::Error<PrintError>> {
        self.check_bearer_token().await?;

        let result = http::apis::invoices_resource_api::print(
            &*self.config.read().await,
            PrintParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?;

        Ok(result)
    }

    pub async fn list_invoices<const P: char>(
        &self,
        customer_id: CustomerId<P>,
    ) -> Result<Vec<InvoiceListItem>, http::apis::Error<ListInvoicesResourceError>> {
        self.check_bearer_token().await?;

        let result = http::apis::invoices_resource_api::list_invoices_resource(
            &*self.config.read().await,
            ListInvoicesResourceParams {
                customernumber: Some(customer_id.to_string()),
                ..Default::default()
            },
        )
        .await?;

        let mut invoices = result.invoices;

        invoices.sort_by(|a, b| {
            if a.invoice_date == b.invoice_date {
                match (a.total, b.total) {
                    (Some(x), Some(y)) => {
                        return x.total_cmp(&y);
                    }
                    _ => {}
                }
            }

            a.invoice_date.cmp(&b.invoice_date)
        });

        Ok(invoices)
    }

    pub async fn send_invoice(
        &self,
        invoice_id: &str,
    ) -> Result<Invoice, http::apis::Error<EmailError>> {
        Ok(*http::apis::invoices_resource_api::email(
            &*self.config.read().await,
            EmailParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?
        .invoice)
    }

    pub async fn create_invoice<const P: char>(
        &self,
        details: CreateInvoice<P>,
    ) -> Result<Invoice, http::apis::Error<CreateInvoicesResourceError>> {
        self.check_bearer_token().await?;

        let result = http::apis::invoices_resource_api::create_invoices_resource(
            &*self.config.read().await,
            CreateInvoicesResourceParams {
                invoice_payload: Some(InvoicePayloadWrap {
                    invoice: Some(Box::new(InvoicePayload {
                        customer_number: details.customer_id.to_string(),
                        due_date: details.due_date.map(|x| x.format("%Y-%m-%d").to_string()),
                        invoice_date: details
                            .invoice_date
                            .map(|x| x.format("%Y-%m-%d").to_string()),
                        invoice_rows: Some(
                            details
                                .items
                                .into_iter()
                                .map(|x| InvoicePayloadInvoiceRow {
                                    account_number: Some(x.account_number as _),
                                    delivered_quantity: Some(x.count.to_string()),
                                    description: Some(x.description),
                                    price: Some(x.price.try_into().unwrap()),
                                    vat: Some(x.vat.into()),
                                    ..Default::default()
                                })
                                .collect(),
                        ),
                        invoice_type: Some(http::models::invoice_payload::InvoiceType::Invoice),
                        terms_of_payment: details.payment_terms,
                        ..Default::default()
                    })),
                }),
            },
        )
        .await?;

        Ok(*result.invoice)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Update<T> {
    #[default]
    Unchanged,
    Null,
    Value(T),
}

impl<T> Update<T> {
    pub fn or_else<F>(self, f: F) -> Update<T>
    where
        F: FnOnce() -> Update<T>,
    {
        match self {
            Update::Unchanged | Update::Null => (f)(),
            Update::Value(v) => Update::Value(v),
        }
    }

    pub fn from_option(v: Option<T>) -> Update<T> {
        match v {
            Some(v) => Update::Value(v),
            None => Update::Null,
        }
    }
}

impl<T> From<T> for Update<T> {
    fn from(value: T) -> Self {
        Update::Value(value)
    }
}

impl<T: Default> From<Update<T>> for Option<T> {
    fn from(value: Update<T>) -> Self {
        match value {
            Update::Unchanged => None,
            Update::Null => Some(T::default()),
            Update::Value(v) => Some(v),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UpdateCustomer {
    pub org_nr: Update<String>,
    pub name: Update<String>,
    pub address1: Update<String>,
    pub address2: Update<String>,
    pub city: Update<String>,
    pub post_code: Update<String>,
    pub country_code: Update<String>,
    pub active: Update<bool>,
    pub email: Update<String>,
    pub email_invoice: Update<String>,
    pub external_reference: Update<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateInvoice<const P: char> {
    pub customer_id: CustomerId<P>,
    pub due_date: Option<NaiveDate>,
    pub invoice_date: Option<NaiveDate>,
    pub payment_terms: Option<String>,
    pub items: Vec<InvoiceItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceItem {
    pub account_number: u16,
    pub count: u32,
    pub description: String,
    pub price: Decimal,
    pub vat: VatSE,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum VatSE {
    Vat0,
    Vat6,
    Vat12,
    #[default]
    Vat25,
}

impl From<VatSE> for i32 {
    fn from(value: VatSE) -> Self {
        match value {
            VatSE::Vat0 => 0,
            VatSE::Vat6 => 6,
            VatSE::Vat12 => 12,
            VatSE::Vat25 => 25,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredentials {
    #[serde(default)]
    pub persistence_path: PathBuf,

    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl OAuthCredentials {
    pub fn save(&self) -> Result<(), std::io::Error> {
        let file = std::fs::File::create(&self.persistence_path)?;
        serde_json::to_writer_pretty(file, &self)?;
        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let mut x: Self = serde_json::from_reader(std::fs::File::open(path.as_ref())?)?;
        x.persistence_path = path.as_ref().to_path_buf();
        Ok(x)
    }
}
