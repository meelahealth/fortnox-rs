use std::error;
use std::fmt;
use std::fmt::Display;

use crate::TokenError;

#[derive(Debug, Clone)]
pub struct ResponseContent<T> {
    pub status: reqwest::StatusCode,
    pub content: String,
    pub entity: Option<T>,
}

impl<T> Display for ResponseContent<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Code: {}; ", self.status)?;
        write!(f, "Content: {}", self.content)
    }
}

#[derive(Debug)]
pub enum Error<T> {
    Reqwest(reqwest::Error),
    Serde(serde_json::Error),
    SerdePath(serde_path_to_error::Error<serde_json::Error>),
    Io(std::io::Error),
    ResponseError(ResponseContent<T>),
    Token(TokenError),
}

impl<T> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (module, e) = match self {
            Error::Reqwest(e) => ("reqwest", e.to_string()),
            Error::Serde(e) => ("serde", e.to_string()),
            Error::SerdePath(e) => ("serde_path_to_error", e.to_string()),
            Error::Io(e) => ("IO", e.to_string()),
            Error::ResponseError(e) => ("response", e.to_string()),
            Error::Token(e) => ("token", format!("{:?}", e)),
        };
        write!(f, "error in {}: {}", module, e)
    }
}

impl<T: fmt::Debug> error::Error for Error<T> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            Error::Reqwest(e) => e,
            Error::Serde(e) => e,
            Error::SerdePath(e) => e,
            Error::Io(e) => e,
            Error::Token(e) => e,
            Error::ResponseError(_) => return None,
        })
    }
}

impl<T> From<reqwest::Error> for Error<T> {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl<T> From<serde_json::Error> for Error<T> {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl<T> From<serde_path_to_error::Error<serde_json::Error>> for Error<T> {
    fn from(e: serde_path_to_error::Error<serde_json::Error>) -> Self {
        Error::SerdePath(e)
    }
}

impl<T> From<std::io::Error> for Error<T> {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl<T> From<TokenError> for Error<T> {
    fn from(value: TokenError) -> Self {
        Error::Token(value)
    }
}

pub fn urlencode<T: AsRef<str>>(s: T) -> String {
    ::url::form_urlencoded::byte_serialize(s.as_ref().as_bytes()).collect()
}

pub fn parse_deep_object(prefix: &str, value: &serde_json::Value) -> Vec<(String, String)> {
    if let serde_json::Value::Object(object) = value {
        let mut params = vec![];

        for (key, value) in object {
            match value {
                serde_json::Value::Object(_) => params.append(&mut parse_deep_object(
                    &format!("{}[{}]", prefix, key),
                    value,
                )),
                serde_json::Value::Array(array) => {
                    for (i, value) in array.iter().enumerate() {
                        params.append(&mut parse_deep_object(
                            &format!("{}[{}][{}]", prefix, key, i),
                            value,
                        ));
                    }
                }
                serde_json::Value::String(s) => {
                    params.push((format!("{}[{}]", prefix, key), s.clone()))
                }
                _ => params.push((format!("{}[{}]", prefix, key), value.to_string())),
            }
        }

        return params;
    }

    unimplemented!("Only objects are supported with style=deepObject")
}

pub mod absence_transactions_resource_api;
pub mod account_charts_resource_api;
pub mod accounts_resource_api;
pub mod archive_resource_api;
pub mod article_file_connections_resource_api;
pub mod articles_resource_api;
pub mod articles_resource_articles_api;
pub mod asset_file_connection_resource_api;
pub mod asset_types_resource_api;
pub mod assets_resource_api;
pub mod attachment_resource_api;
pub mod attendance_transactions_resource_api;
pub mod company_information_resource_api;
pub mod company_settings_resource_api;
pub mod contract_accruals_resource_api;
pub mod contract_templates_resource_api;
pub mod contracts_resource_api;
pub mod cost_centers_resource_api;
pub mod currencies_resource_api;
pub mod custom_document_type_resource_api;
pub mod custom_inbound_document_resource_api;
pub mod custom_outbound_document_resource_api;
pub mod customer_references_resource_api;
pub mod customers_resource_api;
pub mod employees_resource_api;
pub mod eu_vat_limit_regulation_resource_api;
pub mod expenses_resource_api;
pub mod finance_invoices_resource_api;
pub mod financial_years_resource_api;
pub mod inbox_resource_api;
pub mod incoming_goods_resource_api;
pub mod invoice_accruals_resource_api;
pub mod invoice_payments_resource_api;
pub mod invoices_resource_api;
pub mod labels_resource_api;
pub mod locked_period_resource_api;
pub mod me_resource_api;
pub mod modes_of_payments_resource_api;
pub mod offers_resource_api;
pub mod orders_resource_api;
pub mod predefined_accounts_resource_api;
pub mod predefined_voucher_series_resource_api;
pub mod price_lists_resource_api;
pub mod prices_resource_api;
pub mod print_templates_resource_api;
pub mod projects_resource_api;
pub mod purchase_order_resource_api;
pub mod registrations_resource_api;
pub mod salary_transactions_resource_api;
pub mod schedule_times_resource_api;
pub mod sie_resource_api;
pub mod stock_point_resource_api;
pub mod stock_status_resource_api;
pub mod stock_taking_resource_api;
pub mod supplier_invoice_accruals_resource_api;
pub mod supplier_invoice_external_url_connections_resource_api;
pub mod supplier_invoice_file_connections_resource_api;
pub mod supplier_invoice_payments_resource_api;
pub mod supplier_invoices_resource_api;
pub mod suppliers_resource_api;
pub mod tax_reductions_resource_api;
pub mod tenant_resource_api;
pub mod terms_of_deliveries_resource_api;
pub mod terms_of_payments_resource_api;
pub mod trusted_email_senders_resource_api;
pub mod units_resource_api;
pub mod vacation_debt_basis_resource_api;
pub mod voucher_file_connections_resource_api;
pub mod voucher_series_resource_api;
pub mod vouchers_resource_api;
pub mod way_of_deliveries_resource_api;

pub mod configuration;
