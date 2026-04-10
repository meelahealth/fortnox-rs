#[macro_use]
extern crate serde_derive;

pub mod http;
pub mod id;

pub use oauth2;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
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
use rust_decimal::Decimal;
use tokio::sync::{Mutex, MutexGuard};
use url::Url;

use crate::http::apis::customers_resource_api::ListCustomersResourceParams;
use crate::http::apis::invoice_payments_resource_api::{
    GetInvoicePaymentsResourceError, GetInvoicePaymentsResourceParams,
    ListInvoicePaymentsResourceError,
};
use crate::http::apis::invoices_resource_api::{
    UpdateInvoicesResourceError, UpdateInvoicesResourceParams,
};
use crate::http::apis::supplier_invoice_payments_resource_api::{
    BookkeepSupplierInvoicePaymentsResourceError, BookkeepSupplierInvoicePaymentsResourceParams,
    CreateSupplierInvoicePaymentsResourceError, CreateSupplierInvoicePaymentsResourceParams,
    GetSupplierInvoicePaymentsResourceError, GetSupplierInvoicePaymentsResourceParams,
    ListSupplierInvoicePaymentsResourceError,
};
use crate::http::apis::supplier_invoices_resource_api::{
    BookkeepSupplierInvoicesResourceError, BookkeepSupplierInvoicesResourceParams,
    CreateSupplierInvoicesResourceError, CreateSupplierInvoicesResourceParams,
    GetSupplierInvoicesResourceError, GetSupplierInvoicesResourceParams,
};
use crate::http::apis::suppliers_resource_api::{
    CreateSuppliersResourceError, CreateSuppliersResourceParams, GetSuppliersResourceError,
    GetSuppliersResourceParams,
};
use crate::http::models::{
    InvoicePaymentListItem, Supplier, SupplierInvoice, SupplierInvoicePayment,
    SupplierInvoicePaymentListItem, SupplierInvoicePaymentWrap, SupplierInvoiceSupplierInvoiceRow,
    SupplierInvoiceWrap, SupplierWrap,
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
    creds: OAuthCredentials,
    base_path: String,
    client: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckTokenError {
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Client {
    async fn check_bearer_token(&self) -> Result<(), CheckTokenError> {
        if !self.creds.expired().await {
            return Ok(());
        }

        let mut creds = self.creds.lock().await;
        if !creds.expired() {
            // Updated elsewhere
            return Ok(());
        }
        let Some(refresh_token) = creds.refresh_token else {
            // No refresh token, let request fail
            return Ok(());
        };

        let res = self
            .oauth_client
            .exchange_refresh_token(&refresh_token)
            .await?;

        creds.access_token = Some(res.access_token().clone());
        creds.refresh_token = res.refresh_token().cloned();
        creds.expires_at = res
            .expires_in()
            .map(|x| chrono::Duration::seconds(x.as_secs() as i64 - 90))
            .map(|x| Utc::now() + x);

        creds.save().await?;

        Ok(())
    }

    pub fn new(oauth_client: OAuthClient, creds: OAuthCredentials) -> Self {
        let client = reqwest::ClientBuilder::new()
            .user_agent(format!("fortnox-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap();

        Self {
            oauth_client,
            creds,
            base_path: "https://api.fortnox.se".to_string(),
            client,
        }
    }

    async fn config<'a>(&'a self) -> Configuration<'a> {
        let access_token = self.creds.access_token().await;
        Configuration {
            base_path: &self.base_path,
            access_token,
            client: self.client.clone(),
        }
    }

    pub async fn list_customers(
        &self,
    ) -> Result<Vec<CustomerListItem>, Error<ListCustomersResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::customers_resource_api::list_customers_resource(
            &self.config().await,
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
            &self.config().await,
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
            &self.config().await,
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

    pub async fn supplier(
        &self,
        supplier_id: impl ToString,
    ) -> Result<Supplier, Error<GetSuppliersResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::suppliers_resource_api::get_suppliers_resource(
            &self.config().await,
            GetSuppliersResourceParams {
                supplier_number: supplier_id.to_string(),
            },
        )
        .await?;

        Ok(*result.supplier)
    }

    pub async fn supplier_invoice(
        &self,
        given_number: i32,
    ) -> Result<SupplierInvoice, Error<GetSupplierInvoicesResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::supplier_invoices_resource_api::get_supplier_invoices_resource(
            &self.config().await,
            GetSupplierInvoicesResourceParams { given_number },
        )
        .await?;

        Ok(*result.supplier_invoice)
    }

    pub async fn book_supplier_invoice(
        &self,
        given_number: i32,
    ) -> Result<SupplierInvoice, Error<BookkeepSupplierInvoicesResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result =
            http::apis::supplier_invoices_resource_api::bookkeep_supplier_invoices_resource(
                &self.config().await,
                BookkeepSupplierInvoicesResourceParams { given_number },
            )
            .await?;

        Ok(*result.supplier_invoice)
    }

    pub async fn invoice_payment(
        &self,
        number: &str,
    ) -> Result<InvoicePayment, Error<GetInvoicePaymentsResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoice_payments_resource_api::get_invoice_payments_resource(
            &self.config().await,
            GetInvoicePaymentsResourceParams {
                number: number.to_string(),
            },
        )
        .await?;

        Ok(result.invoice_payment)
    }

    pub async fn supplier_invoice_payment(
        &self,
        number: i32,
    ) -> Result<SupplierInvoicePayment, Error<GetSupplierInvoicePaymentsResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::supplier_invoice_payments_resource_api::get_supplier_invoice_payments_resource(
            &self.config().await,
            GetSupplierInvoicePaymentsResourceParams {
                number,
            },
        )
        .await?;

        Ok(result.supplier_invoice_payment)
    }

    pub async fn list_invoice_payment(
        &self,
        invoice_number: &str,
    ) -> Result<Vec<InvoicePaymentListItem>, Error<ListInvoicePaymentsResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoice_payments_resource_api::list_invoice_payments_resource(
            &self.config().await,
            invoice_number,
        )
        .await?;

        Ok(result.invoice_payments)
    }

    pub async fn list_supplier_invoice_payment(
        &self,
        invoice_number: i32,
    ) -> Result<Vec<SupplierInvoicePaymentListItem>, Error<ListSupplierInvoicePaymentsResourceError>>
    {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::supplier_invoice_payments_resource_api::list_supplier_invoice_payments_resource(
            &self.config().await,
            invoice_number,
        )
        .await?;

        Ok(result.supplier_invoice_payments)
    }

    pub async fn create_invoice_payment(
        &self,
        invoice_payment: CreateInvoicePayment,
    ) -> Result<InvoicePayment, Error<CreateInvoicePaymentsResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoice_payments_resource_api::create_invoice_payments_resource(
            &self.config().await,
            CreateInvoicePaymentsResourceParams {
                invoice_payment: InvoicePaymentWrap {
                    invoice_payment: InvoicePayment {
                        invoice_number: invoice_payment.invoice_number,
                        amount_currency: Some(invoice_payment.amount),
                        mode_of_payment: Some(invoice_payment.mode_of_payment),
                        ..Default::default()
                    },
                },
            },
        )
        .await?;

        Ok(result.invoice_payment)
    }

    pub async fn create_supplier_invoice_payment(
        &self,
        invoice_payment: CreateInvoicePayment,
    ) -> Result<SupplierInvoicePayment, Error<CreateSupplierInvoicePaymentsResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::supplier_invoice_payments_resource_api::create_supplier_invoice_payments_resource(
            &self.config().await,
            CreateSupplierInvoicePaymentsResourceParams {
                supplier_invoice_payment: SupplierInvoicePaymentWrap {
                    supplier_invoice_payment: SupplierInvoicePayment {
                        invoice_number: invoice_payment.invoice_number,
                        amount_currency: Some(invoice_payment.amount),
                        mode_of_payment: Some(invoice_payment.mode_of_payment),
                        ..Default::default()
                    }
                }
            },
        )
        .await?;

        Ok(result.supplier_invoice_payment)
    }

    pub async fn book_supplier_invoice_payment(
        &self,
        invoice_payment_number: i32,
    ) -> Result<SupplierInvoicePayment, Error<BookkeepSupplierInvoicePaymentsResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::supplier_invoice_payments_resource_api::bookkeep_supplier_invoice_payments_resource(
            &self.config().await,
            BookkeepSupplierInvoicePaymentsResourceParams {
                number: invoice_payment_number,
            },
        )
        .await?;

        Ok(result.supplier_invoice_payment)
    }

    pub async fn create_customer(
        &self,
        customer_id: impl ToString,
        customer: CreateCustomer,
    ) -> Result<Customer, Error<CreateCustomersResourceError>> {
        self.check_bearer_token().await?;

        let vat_type = match customer.vat_type {
            VatType::Sweden => http::models::customer::VatType::Sevat,
            VatType::ReverseEu => http::models::customer::VatType::Eureversedvat,
            VatType::Export => http::models::customer::VatType::Export,
        };

        fortnox_ratelimit_wait().await;
        let result = http::apis::customers_resource_api::create_customers_resource(
            &self.config().await,
            CreateCustomersResourceParams {
                customer: Some(CustomerWrap {
                    customer: Box::new(Customer {
                        customer_number: Some(customer_id.to_string()),

                        organisation_number: Some(customer.org_nr),
                        vat_type: Some(vat_type),
                        currency: Some(customer.currency),
                        country_code: Some(customer.country_code),
                        external_reference: Some(customer.external_reference),
                        active: Some(customer.active),
                        email: Some(customer.email),
                        email_invoice: Some(customer.email_invoice),
                        name: Some(customer.name),
                        address1: customer.address1,
                        address2: customer.address2,
                        city: customer.city,
                        zip_code: customer.post_code,
                        ..Default::default()
                    }),
                }),
            },
        )
        .await?;

        Ok(*result.customer)
    }

    pub async fn create_supplier(
        &self,
        supplier_id: impl ToString,
        supplier: CreateSupplier,
    ) -> Result<Supplier, Error<CreateSuppliersResourceError>> {
        self.check_bearer_token().await?;

        let vat_type = match supplier.vat_type {
            VatType::Sweden => "0".to_string(),
            VatType::ReverseEu => "0".to_string(),
            VatType::Export => "0".to_string(),
        };

        fortnox_ratelimit_wait().await;
        let result = http::apis::suppliers_resource_api::create_suppliers_resource(
            &self.config().await,
            CreateSuppliersResourceParams {
                supplier: Some(SupplierWrap {
                    supplier: Box::new(Supplier {
                        supplier_number: Some(supplier_id.to_string()),
                        organisation_number: Some(supplier.org_nr),
                        vat_type: Some(vat_type),
                        currency: Some(supplier.currency),
                        country_code: Some(supplier.country_code),
                        active: Some(supplier.active),
                        email: Some(supplier.email),
                        name: supplier.name,
                        address1: supplier.address1,
                        address2: supplier.address2,
                        city: supplier.city,
                        zip_code: supplier.post_code,
                        clearing_number: supplier.clearing_number,
                        bank_account_number: supplier.bank_account_number,
                        bg: supplier.bank_giro,
                        pg: supplier.post_giro,
                        bic: supplier.bic,
                        iban: supplier.iban,
                        ..Default::default()
                    }),
                }),
            },
        )
        .await?;

        Ok(*result.supplier)
    }

    pub async fn create_supplier_invoice(
        &self,
        supplier_id: impl ToString,
        invoice: CreateSupplierInvoice,
    ) -> Result<SupplierInvoice, Error<CreateSupplierInvoicesResourceError>> {
        self.check_bearer_token().await?;

        let sales_type = match invoice.sales_type {
            SalesType::Stock => http::models::supplier_invoice::SalesType::Stock,
            SalesType::Service => http::models::supplier_invoice::SalesType::Service,
        };

        fortnox_ratelimit_wait().await;
        let result = http::apis::supplier_invoices_resource_api::create_supplier_invoices_resource(
            &self.config().await,
            CreateSupplierInvoicesResourceParams {
                supplier_invoice: Some(SupplierInvoiceWrap {
                    supplier_invoice: Box::new(SupplierInvoice {
                        supplier_number: supplier_id.to_string(),
                        given_number: Some(invoice.given_number.to_string()),
                        invoice_number: Some(invoice.invoice_number),
                        ocr: invoice.ocr,
                        due_date: invoice.due_date.map(|d| d.format("%Y-%m-%d").to_string()),
                        invoice_date: invoice
                            .invoice_date
                            .map(|d| d.format("%Y-%m-%d").to_string()),
                        our_reference: invoice.our_reference.clone(),
                        vat: invoice.vat,
                        total: invoice.total,
                        currency: invoice.currency,
                        sales_type: Some(sales_type),
                        supplier_invoice_rows: Some(
                            invoice
                                .items
                                .into_iter()
                                .map(|row| SupplierInvoiceSupplierInvoiceRow {
                                    article_number: row.article_number,
                                    account: Some(row.account_number as i32),
                                    quantity: Some(row.count as i32),
                                    item_description: Some(row.description.clone()),
                                    price: Some(row.price),
                                    total: Some(row.total),
                                    cost_center: row.cost_center,
                                    transaction_information: Some(row.description),
                                    ..Default::default()
                                })
                                .collect(),
                        ),
                        disable_payment_file: Some(invoice.disable_payment_file),
                        ..Default::default()
                    }),
                }),
            },
        )
        .await?;

        Ok(*result.supplier_invoice)
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
            &self.config().await,
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
            &self.config().await,
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
            &self.config().await,
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
            &self.config().await,
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
            &self.config().await,
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
            &self.config().await,
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
            &self.config().await,
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
            &self.config().await,
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
            &self.config().await,
            BookkeepParams {
                number: invoice_payment.number.unwrap().to_string(),
                invoice_payment: Some(InvoicePaymentWrap { invoice_payment }),
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
            &self.config().await,
            CreateInvoicePaymentsResourceParams {
                invoice_payment: InvoicePaymentWrap {
                    invoice_payment: payload,
                },
            },
        )
        .await?;

        Ok(result.invoice_payment)
    }

    pub async fn create_invoice_raw(
        &self,
        payload: InvoicePayload,
    ) -> Result<Invoice, Error<CreateInvoicesResourceError>> {
        self.check_bearer_token().await?;

        fortnox_ratelimit_wait().await;
        let result = http::apis::invoices_resource_api::create_invoices_resource(
            &self.config().await,
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
            &self.config().await,
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
                        language: details.language,
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
            &self.config().await,
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
                        language: details.language,
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

#[derive(Debug, Default)]
pub struct CreateCustomer {
    pub org_nr: String,
    pub vat_type: VatType,
    pub currency: String,
    pub country_code: String,
    pub external_reference: String,
    pub active: bool,
    pub name: String,
    pub email: String,
    pub email_invoice: String,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub post_code: Option<String>,
}

#[derive(Debug, Default)]
pub struct CreateSupplier {
    pub name: String,
    pub org_nr: String,
    pub vat_type: VatType,
    pub currency: String,
    pub country_code: String,
    pub active: bool,

    pub email: String,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub post_code: Option<String>,

    pub clearing_number: Option<String>,
    pub bank_account_number: Option<String>,
    pub bank_giro: Option<String>,
    pub post_giro: Option<String>,
    pub bic: Option<String>,
    pub iban: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum SalesType {
    Stock,
    Service,
}

#[derive(Debug, Clone)]
pub struct CreateSupplierInvoice {
    pub given_number: i32,
    pub invoice_number: String,
    pub ocr: Option<String>,
    pub due_date: Option<NaiveDate>,
    pub invoice_date: Option<NaiveDate>,
    pub our_reference: Option<String>,
    pub language: Option<Language>,
    pub currency: Option<String>,
    pub vat: Option<String>,
    pub total: Option<String>,
    pub items: Vec<SupplierInvoiceItem>,
    pub disable_payment_file: bool,
    pub sales_type: SalesType,
}

#[derive(Debug, Clone)]
pub struct CreateInvoicePayment {
    pub invoice_number: String,
    pub amount: f64,
    pub mode_of_payment: String,
}

#[derive(Debug, Clone)]
pub struct SupplierInvoiceItem {
    pub article_number: Option<String>,
    pub account_number: u16,
    pub count: u32,
    pub description: String,
    pub price: f64,
    pub total: f64,
    pub cost_center: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredentialsData {
    pub access_token: Option<Arc<AccessToken>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub refresh_token: Option<RefreshToken>,
}

pub struct OAuthCredentialsGuard<'a> {
    guard: MutexGuard<'a, CredentialStore>,
    path: &'a Path,
    pub access_token: Option<AccessToken>,
    pub expires_at: Option<DateTime<Utc>>,
    pub refresh_token: Option<RefreshToken>,
}

impl OAuthCredentialsGuard<'_> {
    pub fn expired(&self) -> bool {
        self.expires_at
            .is_none_or(|expires_at| expires_at <= Utc::now())
    }

    pub async fn save(self) -> Result<(), std::io::Error> {
        let Self {
            mut guard,
            path,
            access_token,
            expires_at,
            refresh_token,
        } = self;

        let data = OAuthCredentialsData {
            access_token: access_token.map(Arc::new),
            expires_at,
            refresh_token,
        };

        let buf = serde_json::to_vec_pretty(&data)?;
        fs::File::create(path).await?.write_all(&buf).await?;

        guard.insert(path.to_path_buf(), data);

        Ok(())
    }
}

type CredentialStore = BTreeMap<PathBuf, OAuthCredentialsData>;

static CREDENTIALS_STORE: LazyLock<Mutex<CredentialStore>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

impl OAuthCredentials {
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let mut store = CREDENTIALS_STORE.lock().await;

        let path = path.as_ref();
        if !store.contains_key(path) && path.try_exists()? {
            let mut buf = Vec::new();
            fs::File::open(path).await?.read_to_end(&mut buf).await?;
            let data: OAuthCredentialsData = serde_json::from_slice(&buf)?;

            store.insert(path.to_path_buf(), data);
        }

        Ok(OAuthCredentials {
            persistence_path: path.to_path_buf(),
        })
    }

    pub async fn expired(&self) -> bool {
        let store = CREDENTIALS_STORE.lock().await;
        store
            .get(&self.persistence_path)
            .and_then(|c| c.expires_at)
            .is_none_or(|expires_at| expires_at <= Utc::now())
    }

    pub async fn access_token(&self) -> Option<Arc<AccessToken>> {
        let store = CREDENTIALS_STORE.lock().await;
        store
            .get(&self.persistence_path)
            .and_then(|c| c.access_token.clone())
    }

    pub async fn lock<'a>(&'a self) -> OAuthCredentialsGuard<'a> {
        let store = CREDENTIALS_STORE.lock().await;
        let data = store.get(&self.persistence_path);
        let access_token = data.and_then(|c| c.access_token.as_deref()).cloned();
        let expires_at = data.and_then(|c| c.expires_at);
        let refresh_token = data.and_then(|c| c.refresh_token.clone());

        OAuthCredentialsGuard {
            guard: store,
            path: &self.persistence_path,
            access_token,
            expires_at,
            refresh_token,
        }
    }
}

/// Wait for available request token
/// Based on limits at https://www.fortnox.se/developer/guides-and-good-to-know/rate-limits-for-fortnox-api
pub(crate) async fn fortnox_ratelimit_wait() {
    static RATELIMIT: LazyLock<ratelimit::Ratelimiter> = LazyLock::new(|| {
        // Limit below, trying to compensate for sliding window
        ratelimit::Ratelimiter::builder(4, Duration::from_secs(1))
            .max_tokens(4)
            .build()
            .expect("Failed to create ratelimit instance")
    });
    while let Err(d) = RATELIMIT.try_wait() {
        tokio::time::sleep(d).await;
    }
}
