#[macro_use]
extern crate serde_derive;

pub mod http;
pub mod id;

pub use oauth2;

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use http::apis::configuration::Configuration;
use http::apis::customers_resource_api::{
    CreateCustomersResourceError, CreateCustomersResourceParams, GetCustomersResourceError,
    GetCustomersResourceParams, ListCustomersResourceError, UpdateCustomersResourceError,
    UpdateCustomersResourceParams,
};
use http::apis::invoice_payments_resource_api::{
    BookkeepError, BookkeepParams, CreateInvoicePaymentsResourceError,
    CreateInvoicePaymentsResourceParams,
};
use http::apis::invoices_resource_api::{
    BookkeepInvoicesResourceError, BookkeepInvoicesResourceParams, CreateInvoicesResourceError,
    CreateInvoicesResourceParams, CreditError, CreditParams, EmailError, EmailParams,
    ExternalPrintError, ExternalPrintParams, GetInvoicesResourceError, GetInvoicesResourceParams,
    ListInvoicesResourceError, ListInvoicesResourceParams, PrintError, PrintParams,
};
pub use http::apis::Error;
pub use http::models::invoice_payload::Language;
use http::models::{
    BookedInvoicePayment, Customer, CustomerListItem, CustomerWrap, Invoice, InvoiceListItem,
    InvoicePayload, InvoicePayloadInvoiceRow, InvoicePayloadWrap, InvoicePayment,
    InvoicePaymentWrap,
};
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

use crate::http::apis::customers_resource_api::ListCustomersResourceParams;
use crate::http::apis::invoices_resource_api::{
    UpdateInvoicesResourceError, UpdateInvoicesResourceParams,
};

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
        fortnox_ratelimit_wait().await;
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
        fortnox_ratelimit_wait().await;
        let result = self
            .0
            .exchange_refresh_token(refresh_token)
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

fn make_http_client(access_token: Option<&AccessToken>) -> reqwest::Client {
    let mut headers = header::HeaderMap::new();

    if let Some(access_token) = access_token.as_ref() {
        headers.insert(
            "Authorization",
            header::HeaderValue::from_str(&format!("Bearer {}", access_token.secret())).unwrap(),
        );
    }

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
            let Some(creds) = creds.data.as_ref() else {
                return Ok(());
            };

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

        let mut creds_parent = self.creds.write().await;
        let Some(creds) = creds_parent.data.as_mut() else {
            return Ok(());
        };

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

        self.config.write().await.client = make_http_client(Some(res.access_token()));

        creds.access_token = Some(res.access_token().clone());
        creds.refresh_token = res.refresh_token().cloned();
        creds.expires_at = res
            .expires_in()
            .map(|x| chrono::Duration::seconds(x.as_secs() as i64 - 90))
            .map(|x| Utc::now() + x);

        creds_parent.save().unwrap();

        Ok(())
    }

    pub fn new(oauth_client: OAuthClient, creds: OAuthCredentials) -> Self {
        let config = Configuration {
            base_path: "https://api.fortnox.se".to_string(),
            user_agent: Some(format!("fortnox-rs/{}", env!("CARGO_PKG_VERSION"))),
            client: make_http_client(creds.data.as_ref().and_then(|x| x.access_token.as_ref())),
        };

        Self {
            oauth_client,
            config: RwLock::from(config),
            creds: RwLock::from(creds),
        }
    }

    pub async fn set_credentials(&self, creds: OAuthCredentialsData) -> Result<(), std::io::Error> {
        let mut guard = self.creds.write().await;
        guard.data = Some(creds);
        guard.save()?;
        Ok(())
    }

    pub async fn list_customers(
        &self,
    ) -> Result<Vec<CustomerListItem>, Error<ListCustomersResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::customers_resource_api::list_customers_resource(
            &*self.config.read().await,
            ListCustomersResourceParams { filter: None },
        )
        .await?;

        Ok(result
            .customers
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>())
    }

    pub async fn customer(
        &self,
        id: impl AsRef<str>,
    ) -> Result<Customer, Error<GetCustomersResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::customers_resource_api::get_customers_resource(
            &*self.config.read().await,
            GetCustomersResourceParams {
                customer_number: id.as_ref().to_string(),
            },
        )
        .await?;

        Ok(*result.customer)
    }

    pub async fn create_or_update_customer(
        &self,
        customer_id: impl AsRef<str>,
        details: UpdateCustomer,
    ) -> Result<Customer, Error<CreateCustomersResourceError>> {
        match self
            .update_customer(customer_id.as_ref(), details.clone())
            .await
        {
            Ok(v) => return Ok(v),
            Err(_e) => {}
        }

        self.create_customer(customer_id, details).await
    }

    pub async fn create_customer(
        &self,
        customer_id: impl AsRef<str>,
        details: UpdateCustomer,
    ) -> Result<Customer, Error<CreateCustomersResourceError>> {
        self.check_bearer_token().await?;

        let vat_type = match details.vat_type {
            Update::Unchanged => Update::Unchanged,
            Update::Null => Update::Null,
            Update::Value(x) => Update::Value(match x {
                VatType::Sweden => http::models::customer::VatType::Sevat,
                VatType::ReverseEu => http::models::customer::VatType::Eureversedvat,
                VatType::Export => http::models::customer::VatType::Export,
            }),
        };

        fortnox_ratelimit_wait().await;
        let result = http::apis::customers_resource_api::create_customers_resource(
            &*self.config.read().await,
            CreateCustomersResourceParams {
                customer: Some(CustomerWrap {
                    customer: Box::new(Customer {
                        customer_number: customer_id.as_ref().to_string().clone().into(),
                        organisation_number: details.org_nr.clone().into(),
                        name: details.name.clone().into(),
                        address1: details.address1.clone().into(),
                        address2: details.address2.clone().into(),
                        city: details.city.clone().into(),
                        zip_code: details.post_code.clone().into(),
                        country_code: details.country_code.clone().into(),
                        active: details.active.clone().into(),
                        email_invoice: details
                            .email_invoice
                            .clone()
                            .or_else(|| details.email.clone())
                            .clone()
                            .into(),
                        email: details.email.clone().into(),
                        external_reference: details.external_reference.clone().into(),
                        vat_type: vat_type.clone().into(),
                        currency: details.currency.clone().into(),
                        ..Default::default()
                    }),
                }),
            },
        )
        .await?;

        Ok(*result.customer)
    }

    pub async fn update_customer(
        &self,
        id: impl AsRef<str>,
        details: UpdateCustomer,
    ) -> Result<Customer, Error<UpdateCustomersResourceError>> {
        self.check_bearer_token().await?;

        let vat_type = match details.vat_type {
            Update::Unchanged => Update::Unchanged,
            Update::Null => Update::Null,
            Update::Value(x) => Update::Value(match x {
                VatType::Sweden => http::models::customer::VatType::Sevat,
                VatType::ReverseEu => http::models::customer::VatType::Eureversedvat,
                VatType::Export => http::models::customer::VatType::Export,
            }),
        };

        fortnox_ratelimit_wait().await;
        let result = http::apis::customers_resource_api::update_customers_resource(
            &*self.config.read().await,
            UpdateCustomersResourceParams {
                customer_number: id.as_ref().to_string(),
                customer: CustomerWrap {
                    customer: Box::new(Customer {
                        organisation_number: details.org_nr.clone().into(),
                        name: details.name.clone().into(),
                        address1: details.address1.clone().into(),
                        address2: details.address2.clone().into(),
                        city: details.city.clone().into(),
                        zip_code: details.post_code.clone().into(),
                        country_code: details.country_code.clone().into(),
                        active: details.active.clone().into(),
                        email_invoice: details
                            .email_invoice
                            .clone()
                            .or_else(|| details.email.clone())
                            .clone()
                            .into(),
                        email: details.email.clone().into(),
                        external_reference: details.external_reference.clone().into(),
                        vat_type: vat_type.clone().into(),
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
    ) -> Result<Invoice, Error<BookkeepInvoicesResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
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
    ) -> Result<Invoice, Error<GetInvoicesResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoices_resource_api::get_invoices_resource(
            &*self.config.read().await,
            GetInvoicesResourceParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?;

        Ok(*result.invoice)
    }

    pub async fn refund_invoice(&self, invoice_id: &str) -> Result<Invoice, Error<CreditError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoices_resource_api::credit(
            &*self.config.read().await,
            CreditParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?;

        Ok(*result.invoice)
    }

    pub async fn mark_invoice_sent(
        &self,
        invoice_id: &str,
    ) -> Result<Invoice, Error<ExternalPrintError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoices_resource_api::external_print(
            &*self.config.read().await,
            ExternalPrintParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?;

        Ok(*result.invoice)
    }

    pub async fn download_invoice_pdf(
        &self,
        invoice_id: &str,
    ) -> Result<Vec<u8>, Error<PrintError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoices_resource_api::print(
            &*self.config.read().await,
            PrintParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?;

        Ok(result)
    }

    pub async fn list_invoices(
        &self,
        customer_id: &str,
        external_invoice_reference1: Option<&str>,
    ) -> Result<Vec<InvoiceListItem>, Error<ListInvoicesResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoices_resource_api::list_invoices_resource(
            &*self.config.read().await,
            ListInvoicesResourceParams {
                customernumber: Some(customer_id.to_string()),
                externalinvoicereference1: external_invoice_reference1.map(str::to_string),
                ..Default::default()
            },
        )
        .await?;

        let mut invoices = result.invoices;

        invoices.sort_by(|a, b| {
            if a.invoice_date == b.invoice_date {
                if let (Some(x), Some(y)) = (a.total, b.total) {
                    return x.total_cmp(&y);
                }
            }

            a.invoice_date.cmp(&b.invoice_date)
        });

        Ok(invoices)
    }

    pub async fn send_invoice(&self, invoice_id: &str) -> Result<Invoice, Error<EmailError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoices_resource_api::email(
            &*self.config.read().await,
            EmailParams {
                document_number: invoice_id.to_string(),
            },
        )
        .await?;

        Ok(*result.invoice)
    }

    pub async fn book_invoice_payment(
        &self,
        invoice_payment: InvoicePayment,
    ) -> Result<BookedInvoicePayment, Error<BookkeepError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoice_payments_resource_api::bookkeep(
            &*self.config.read().await,
            BookkeepParams {
                number: invoice_payment.number.unwrap().to_string(),
                invoice_payment: Some(InvoicePaymentWrap {
                    invoice_payment: Some(Box::new(invoice_payment.clone())),
                }),
            },
        )
        .await?;

        Ok(*result.invoice_payment.unwrap())
    }

    pub async fn create_invoice_payment_raw(
        &self,
        payload: InvoicePayment,
    ) -> Result<InvoicePayment, Error<CreateInvoicePaymentsResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoice_payments_resource_api::create_invoice_payments_resource(
            &*self.config.read().await,
            CreateInvoicePaymentsResourceParams {
                invoice_payment: Some(InvoicePaymentWrap {
                    invoice_payment: Some(Box::new(payload.clone())),
                }),
            },
        )
        .await?;

        Ok(*result.invoice_payment.unwrap())
    }

    pub async fn create_invoice_raw(
        &self,
        payload: InvoicePayload,
    ) -> Result<Invoice, Error<CreateInvoicesResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoices_resource_api::create_invoices_resource(
            &*self.config.read().await,
            CreateInvoicesResourceParams {
                invoice_payload: Some(InvoicePayloadWrap {
                    invoice: Some(Box::new(payload.clone())),
                }),
            },
        )
        .await?;

        Ok(*result.invoice)
    }

    pub async fn create_invoice(
        &self,
        details: CreateInvoice,
    ) -> Result<Invoice, Error<CreateInvoicesResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
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
                                .clone()
                                .items
                                .iter()
                                .map(|x| InvoicePayloadInvoiceRow {
                                    article_number: x.article_number.clone(),
                                    account_number: Some(x.account_number as _),
                                    delivered_quantity: Some(x.count.to_string()),
                                    description: Some(x.description.clone()),
                                    price: Some(x.price.try_into().unwrap()),
                                    vat: Some(x.vat.into()),
                                    cost_center: x.cost_center.clone(),
                                    ..Default::default()
                                })
                                .collect(),
                        ),
                        invoice_type: Some(http::models::invoice_payload::InvoiceType::Invoice),
                        terms_of_payment: details.payment_terms.clone(),
                        remarks: details.comment.clone(),
                        your_reference: details.your_reference.clone(),
                        language: details.language.clone(),
                        currency: details.currency.clone(),
                        external_invoice_reference1: details.external_invoice_reference1.clone(),
                        ..Default::default()
                    })),
                }),
            },
        )
        .await?;

        Ok(*result.invoice)
    }

    pub async fn update_invoice(
        &self,
        invoice_id: &str,
        details: UpdateInvoice,
    ) -> Result<Invoice, Error<UpdateInvoicesResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoices_resource_api::update_invoices_resource(
            &*self.config.read().await,
            UpdateInvoicesResourceParams {
                document_number: invoice_id.to_string(),
                invoice_payload: Some(InvoicePayloadWrap {
                    invoice: Some(Box::new(InvoicePayload {
                        customer_number: details.customer_id.to_string(),
                        due_date: details.due_date.map(|x| x.format("%Y-%m-%d").to_string()),
                        invoice_date: details
                            .invoice_date
                            .map(|x| x.format("%Y-%m-%d").to_string()),
                        invoice_rows: Some(details.clone().items.clone()),
                        invoice_type: Some(http::models::invoice_payload::InvoiceType::Invoice),
                        terms_of_payment: details.payment_terms.clone(),
                        remarks: details.comment.clone(),
                        your_reference: details.your_reference.clone(),
                        language: details.language.clone(),
                        currency: details.currency.clone(),
                        ..Default::default()
                    })),
                }),
            },
        )
        .await?;

        Ok(*result.invoice)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub vat_type: Update<VatType>,
    pub currency: Update<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInvoice {
    pub customer_id: String,
    pub due_date: Option<NaiveDate>,
    pub invoice_date: Option<NaiveDate>,
    pub payment_terms: Option<String>,
    pub items: Vec<InvoiceItem>,
    pub comment: Option<String>,
    pub your_reference: Option<String>,
    pub language: Option<Language>,
    pub currency: Option<String>,
    pub external_invoice_reference1: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateInvoice {
    pub customer_id: String,
    pub due_date: Option<NaiveDate>,
    pub invoice_date: Option<NaiveDate>,
    pub payment_terms: Option<String>,
    // Account number might not be set because we are adding a line item that is just a comment effectively
    pub items: Vec<InvoicePayloadInvoiceRow>,
    pub comment: Option<String>,
    pub your_reference: Option<String>,
    pub language: Option<Language>,
    pub currency: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceItem {
    pub article_number: Option<String>,
    // TODO: how are we able to deal with the fact that our own is u16 but theirs is i32? Worrying...
    pub account_number: u16,
    pub count: u32,
    pub description: String,
    pub price: Decimal,
    pub vat: VatSE,
    pub cost_center: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub enum VatType {
    #[default]
    Sweden,
    ReverseEu,
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone)]
pub struct OAuthCredentials {
    pub persistence_path: PathBuf,
    pub data: Option<OAuthCredentialsData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredentialsData {
    pub access_token: Option<AccessToken>,
    pub refresh_token: Option<RefreshToken>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl OAuthCredentials {
    pub fn save(&self) -> Result<(), std::io::Error> {
        if let Some(data) = self.data.as_ref() {
            let file = std::fs::File::create(&self.persistence_path)?;
            serde_json::to_writer_pretty(file, data)?;
        }
        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let file = match std::fs::File::open(path.as_ref()) {
            Ok(v) => v,
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => {
                    return Ok(OAuthCredentials {
                        persistence_path: path.as_ref().to_path_buf(),
                        data: None,
                    })
                }
                _ => return Err(e),
            },
        };

        let data: OAuthCredentialsData = serde_json::from_reader(file)?;
        Ok(OAuthCredentials {
            persistence_path: path.as_ref().to_path_buf(),
            data: Some(data),
        })
    }
}

/// Wait for available request token
/// Based on limits at https://www.fortnox.se/developer/guides-and-good-to-know/rate-limits-for-fortnox-api
pub(crate) async fn fortnox_ratelimit_wait() {
    static RATELIMIT: LazyLock<ratelimit::Ratelimiter> = LazyLock::new(|| {
        // Limit slightly below limit
        ratelimit::Ratelimiter::builder(20, Duration::from_secs(5))
            .max_tokens(20) // No bursts
            .build()
            .expect("Failed to create ratelimit instance")
    });
    while let Err(d) = RATELIMIT.try_wait() {
        tokio::time::sleep(d).await;
    }
}
