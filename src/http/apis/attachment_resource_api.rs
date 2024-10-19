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

/// struct for passing parameters to the method [`attach`]
#[derive(Clone, Debug, Default)]
pub struct AttachParams {
    /// A list of attachments
    pub attachments: Option<Vec<crate::http::models::Attachment>>,
}

/// struct for passing parameters to the method [`detach`]
#[derive(Clone, Debug, Default)]
pub struct DetachParams {
    /// id of the attachment to be detached
    pub attachment_id: String,
}

/// struct for passing parameters to the method [`get_attachments`]
#[derive(Clone, Debug, Default)]
pub struct GetAttachmentsParams {
    /// ids of the entities whose attachments should be fetched
    pub entityid: Vec<i64>,
    /// type of the entities whose attachments should be fetched
    pub entitytype: String,
}

/// struct for passing parameters to the method [`get_number_of_attachments_for_entity`]
#[derive(Clone, Debug, Default)]
pub struct GetNumberOfAttachmentsForEntityParams {
    /// ids of the entities to look for number of attachments on
    pub entityids: Vec<i64>,
    /// type of the entities  to look for number of attachments on
    pub entitytype: String,
}

/// struct for passing parameters to the method [`update_attachment`]
#[derive(Clone, Debug, Default)]
pub struct UpdateAttachmentParams {
    /// id of the attachment to be updated
    pub attachment_id: String,
    /// an attachment
    pub attachment: Option<crate::http::models::Attachment>,
}

/// struct for passing parameters to the method [`validate_included_on_send`]
#[derive(Clone, Debug, Default)]
pub struct ValidateIncludedOnSendParams {
    /// a list of Attachments
    pub attachments: Option<Vec<crate::http::models::Attachment>>,
}

/// struct for typed errors of method [`attach`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttachError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`detach`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DetachError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_attachments`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAttachmentsError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_number_of_attachments_for_entity`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetNumberOfAttachmentsForEntityError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`update_attachment`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateAttachmentError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`validate_included_on_send`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ValidateIncludedOnSendError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

pub async fn attach(
    configuration: &configuration::Configuration,
    params: AttachParams,
) -> Result<Vec<crate::http::models::Attachment>, Error<AttachError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let attachments = params.attachments;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/fileattachments/attachments-v1",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&attachments);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<AttachError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn detach(
    configuration: &configuration::Configuration,
    params: DetachParams,
) -> Result<(), Error<DetachError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let attachment_id = params.attachment_id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/fileattachments/attachments-v1/{attachmentId}",
        local_var_configuration.base_path,
        attachmentId = crate::http::apis::urlencode(attachment_id)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::DELETE, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        Ok(())
    } else {
        let local_var_entity: Option<DetachError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn get_attachments(
    configuration: &configuration::Configuration,
    params: GetAttachmentsParams,
) -> Result<Vec<crate::http::models::Attachment>, Error<GetAttachmentsError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let entityid = params.entityid;
    let entitytype = params.entitytype;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/fileattachments/attachments-v1",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    local_var_req_builder = match "multi" {
        "multi" => local_var_req_builder.query(
            &entityid
                .into_iter()
                .map(|p| ("entityid".to_owned(), p.to_string()))
                .collect::<Vec<(std::string::String, std::string::String)>>(),
        ),
        _ => local_var_req_builder.query(&[(
            "entityid",
            &entityid
                .into_iter()
                .map(|p| p.to_string())
                .collect::<Vec<String>>()
                .join(","),
        )]),
    };
    local_var_req_builder = local_var_req_builder.query(&[("entitytype", &entitytype.to_string())]);
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
        let local_var_entity: Option<GetAttachmentsError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn get_number_of_attachments_for_entity(
    configuration: &configuration::Configuration,
    params: GetNumberOfAttachmentsForEntityParams,
) -> Result<
    Vec<crate::http::models::NumberOfAttachments>,
    Error<GetNumberOfAttachmentsForEntityError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let entityids = params.entityids;
    let entitytype = params.entitytype;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/fileattachments/attachments-v1/numberofattachments",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    local_var_req_builder = match "multi" {
        "multi" => local_var_req_builder.query(
            &entityids
                .into_iter()
                .map(|p| ("entityids".to_owned(), p.to_string()))
                .collect::<Vec<(std::string::String, std::string::String)>>(),
        ),
        _ => local_var_req_builder.query(&[(
            "entityids",
            &entityids
                .into_iter()
                .map(|p| p.to_string())
                .collect::<Vec<String>>()
                .join(","),
        )]),
    };
    local_var_req_builder = local_var_req_builder.query(&[("entitytype", &entitytype.to_string())]);
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
        let local_var_entity: Option<GetNumberOfAttachmentsForEntityError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn update_attachment(
    configuration: &configuration::Configuration,
    params: UpdateAttachmentParams,
) -> Result<crate::http::models::Attachment, Error<UpdateAttachmentError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let attachment_id = params.attachment_id;
    let attachment = params.attachment;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/fileattachments/attachments-v1/{attachmentId}",
        local_var_configuration.base_path,
        attachmentId = crate::http::apis::urlencode(attachment_id)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&attachment);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<UpdateAttachmentError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn validate_included_on_send(
    configuration: &configuration::Configuration,
    params: ValidateIncludedOnSendParams,
) -> Result<(), Error<ValidateIncludedOnSendError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let attachments = params.attachments;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/fileattachments/attachments-v1/validateincludedonsend",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&attachments);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        Ok(())
    } else {
        let local_var_entity: Option<ValidateIncludedOnSendError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
