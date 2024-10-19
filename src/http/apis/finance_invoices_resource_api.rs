/*
 * # Documentation   The Fortnox API is organized around REST. This means that we’ve designed it to have resource-oriented URLs and be as predictable as possible for you as developer.  It also means that we use HTTP status codes when something goes wrong and HTTP verbs understod by many API clients around the web.  We use a modified version of OAuth2 for authentication to offer a secure way for both you and our users to interact.  The API is generally built to support both XML and JSON but in this documentation all the examples will be in JSON.  We encourage you to read all the articles in the [general information section](https://developer.fortnox.se/general/)</a> first, before going forward and learning about the different resources.  This to ensure you get an understanding of some of the shared components of the API such as parameters and error handling.  ## Rate limits  The limit is 4 requests per second per access-token. This equals to a bit more than 200 requests per minute.  [Read more about this here.](https://developer.fortnox.se/general/regarding-fortnox-api-rate-limits/)  ## Query parameters  Use query parameters with the ?-character and separate parameters with the &-character.   **Example:**  GET - https://api.fortnox.se/3/invoices?accountnumberfrom=3000&accountnumberto=4000 Read more about our parameters [here](https://developer.fortnox.se/general/parameters/)   Search the documentation using the search field in the top left corner.
 *
 * The version of the OpenAPI document: 1.0.0
 *
 * Generated by: https://openapi-generator.tech
 */

use reqwest;

use super::{configuration, Error};
use crate::http::apis::ResponseContent;

/// struct for passing parameters to the method [`create_finance_invoices_resource`]
#[derive(Clone, Debug, Default)]
pub struct CreateFinanceInvoicesResourceParams {
    /// The payload for sending an invoice with  Fortnox Finans
    pub payload: Option<crate::http::models::CreatePayloadWrap>,
}

/// struct for passing parameters to the method [`get_finance_invoices_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetFinanceInvoicesResourceParams {
    /// The Fortnox invoice number
    pub number: String,
}

/// struct for passing parameters to the method [`pause`]
#[derive(Clone, Debug, Default)]
pub struct PauseParams {
    /// The Fortnox invoice number
    pub number: String,
    /// The payload for sending an invoice with  Fortnox Finans
    pub payload: Option<crate::http::models::PausePayloadWrap>,
}

/// struct for passing parameters to the method [`report_payment`]
#[derive(Clone, Debug, Default)]
pub struct ReportPaymentParams {
    /// The Fortnox invoice number
    pub number: String,
    /// The payload for sending an invoice with  Fortnox Finans
    pub payload: Option<crate::http::models::ReportPaymentPayload>,
}

/// struct for passing parameters to the method [`stop`]
#[derive(Clone, Debug, Default)]
pub struct StopParams {
    /// The Fortnox invoice number
    pub number: String,
}

/// struct for passing parameters to the method [`take_fees`]
#[derive(Clone, Debug, Default)]
pub struct TakeFeesParams {
    /// The Fortnox invoice number
    pub number: String,
}

/// struct for passing parameters to the method [`unpause`]
#[derive(Clone, Debug, Default)]
pub struct UnpauseParams {
    /// The Fortnox invoice number
    pub number: String,
}

/// struct for typed errors of method [`create_finance_invoices_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CreateFinanceInvoicesResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_finance_invoices_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetFinanceInvoicesResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`pause`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PauseError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`report_payment`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReportPaymentError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`stop`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StopError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`take_fees`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TakeFeesError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`unpause`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UnpauseError {
    UnknownValue(serde_json::Value),
}

/// <p>  When sending an invoice with Fortnox Finans you will get the invoice status returned if everything succeeded,  if there were any problems, an error will be returned.  <p>  Please note that it can take 1 min to several hours before you will get back status, OCR number and link to  PDF document, meanwhile the invoice will have status UNKNOWN or NOT_AUTHORIZED.  <p>  Fortnox Finans is currently only accepting invoices in SEK  <p>  <i>Parameters in the body:</i>  <ul>      <li><b>InvoiceNumber</b>: the invoice number for the invoice which should be sent with Fortnox Finans</li>      <li><b>SendMethod</b>: how to send the invoice; EMAIL, LETTER, EINVOICE or NONE</li>      <li><b>Service</b>: which service to use; LEDGERBASE or REMINDER</li>  </ul>  <p>
pub async fn create_finance_invoices_resource(
    configuration: &configuration::Configuration,
    params: CreateFinanceInvoicesResourceParams,
) -> Result<crate::http::models::InvoiceResponseWrap, Error<CreateFinanceInvoicesResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let payload = params.payload;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/noxfinansinvoices/", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&payload);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CreateFinanceInvoicesResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// <p>  Retrieves the status and balance of an invoice sent to Fortnox Finans.  You need to supply the invoice number in Fortox to retrieve the invoice.  <p>  <b>Note that</b> invoices sent with the old &quot;Noxbox&quot; platform will not have the &quot;ServiceName&quot;  property in the response. This new property is added to the response if the invoice is  sent with the new finance service.  <p>  Response explanation for <b>Service</b> and <b>ServiceName</b>  <p>  <b>Service:</b>  <ul>      <li><b>LEDGERBASE</b>: if the invoice is sent by using the old &quot;Noxbox&quot; platform, or the new finance service with the subtypes &quot;Service Full&quot; or &quot;Service Light&quot;. These services are explained above in the &quot;Fortnox Finans services&quot; section</li>      <li><b>REMINDER</b>: If the invoice is sent by the new finance service, with the service Reminder Service</li>  </ul>  <p>  <b>ServiceName</b> (only provided for <u>new finance service</u> invoices):  <ul>      <li><b>SERVICE_FULL</b>: Ledgerbase service <u>with</u> automatic reminders is used</li>      <li><b>SERVICE_LIGHT</b>: Ledgerbase service <u>without</u> automatic reminders is used.</li>      <li><b>REMINDER_SERVICE</b>: Reminder service is used</li>  </ul>
pub async fn get_finance_invoices_resource(
    configuration: &configuration::Configuration,
    params: GetFinanceInvoicesResourceParams,
) -> Result<crate::http::models::InvoiceResponseWrap, Error<GetFinanceInvoicesResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let number = params.number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/noxfinansinvoices/{Number}",
        local_var_configuration.base_path,
        Number = crate::http::apis::urlencode(number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<GetFinanceInvoicesResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// <p>  Pauses an invoice for up to 60 days. Pause means that Fortnox Finans reminder process will stop for the invoice. All invoices which have the status OPEN can be paused.  <p>  <i>Parameters in the body:</i>  <ul>      <li><b>PausedUntilDate</b>: the invoice will be paused to and including this date.</li>  </ul>  <p>
pub async fn pause(
    configuration: &configuration::Configuration,
    params: PauseParams,
) -> Result<crate::http::models::InvoiceResponseWrap, Error<PauseError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let number = params.number;
    let payload = params.payload;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/noxfinansinvoices/{Number}/pause",
        local_var_configuration.base_path,
        Number = crate::http::apis::urlencode(number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&payload);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<PauseError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// <p>  If a customer has paid some or all of the capital on an invoice directly to the client, this can be reported  for bookkeeping purposes and reported to Fortnox Finans to actually deduct the paid amount from the invoice.  <p>  <b>Note:</b> this action is <b>not</b> available for invoices sent by the old Noxbox platform  <p>  <i>Parameters in the body:</i>  <ul>      <li><b>ClientTakesFees</b>: a boolean indicating if the client should take the customer fees or not.</li>      <li><b>BookkeepPaymentInFortnox</b>: a boolean indicating if the payment should be bookkept in Fortnox or not. Usually the payment should be bookkept.</li>      <li><b>ReportToFinance</b>: a boolean indicating if the payment should be reported to Fortnox Finans or not. Usually the payment should be reported.</li>      <li><b>PaymentAmount</b>: a decimal field with the amount to report.</li>      <li><b>PaymentMethodCode</b>: a string with the method code (e.g. BG, PG or other). Could be omitted if BookkeepPaymentInFortnox is false.</li>      <li><b>PaymentMethodAccount</b>: an integer with the account number to bookkeep the payment on (e.g. 1920 or other). Could be omitted if BookkeepPaymentInFortnox is false.</li>  </ul>  <p>
pub async fn report_payment(
    configuration: &configuration::Configuration,
    params: ReportPaymentParams,
) -> Result<crate::http::models::InvoiceResponseWrap, Error<ReportPaymentError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let number = params.number;
    let payload = params.payload;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/noxfinansinvoices/{Number}/report-payment",
        local_var_configuration.base_path,
        Number = crate::http::apis::urlencode(number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&payload);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<ReportPaymentError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// <p>  Removes the invoice from Fortnox Finans process. The invoice can still be handled manually, but no further automatic process will be applied  <p>
pub async fn stop(
    configuration: &configuration::Configuration,
    params: StopParams,
) -> Result<crate::http::models::InvoiceResponseWrap, Error<StopError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let number = params.number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/noxfinansinvoices/{Number}/stop",
        local_var_configuration.base_path,
        Number = crate::http::apis::urlencode(number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<StopError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// <p>  If fees have been added to an invoice, e.g. reminder fees, the client can choose to pay those fees instead of letting the customer pay.  <p>  <b>Note:</b> this action is <b>not</b> available for invoices sent by the old Noxbox platform
pub async fn take_fees(
    configuration: &configuration::Configuration,
    params: TakeFeesParams,
) -> Result<crate::http::models::InvoiceResponseWrap, Error<TakeFeesError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let number = params.number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/noxfinansinvoices/{Number}/take-fees",
        local_var_configuration.base_path,
        Number = crate::http::apis::urlencode(number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<TakeFeesError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// <p>  Unpauses a paused invoice. If the invoice is manually paused, then this action will remove the pause status immediately. Invoices which are paused by the system cannot be unpaused.  <p>  <b>Note:</b> this action is <b>not</b> available for invoices sent by the old Noxbox platform
pub async fn unpause(
    configuration: &configuration::Configuration,
    params: UnpauseParams,
) -> Result<crate::http::models::InvoiceResponseWrap, Error<UnpauseError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let number = params.number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/noxfinansinvoices/{Number}/unpause",
        local_var_configuration.base_path,
        Number = crate::http::apis::urlencode(number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<UnpauseError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
