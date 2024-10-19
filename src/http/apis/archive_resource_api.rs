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

/// struct for passing parameters to the method [`get_file_by_id`]
#[derive(Clone, Debug, Default)]
pub struct GetFileByIdParams {
    /// identifies the file
    pub id: String,
    /// fileId from fileattachments
    pub fileid: Option<String>,
}

/// struct for passing parameters to the method [`get_folder`]
#[derive(Clone, Debug, Default)]
pub struct GetFolderParams {
    /// name of folder
    pub path: Option<String>,
    /// fileId from fileattachments
    pub fileid: Option<String>,
}

/// struct for passing parameters to the method [`remove_by_id`]
#[derive(Clone, Debug, Default)]
pub struct RemoveByIdParams {
    /// identifies file/folder to remove
    pub id: String,
}

/// struct for passing parameters to the method [`remove_by_path`]
#[derive(Clone, Debug, Default)]
pub struct RemoveByPathParams {
    /// identifies file/folder to remove
    pub path: Option<String>,
}

/// struct for passing parameters to the method [`upload_file`]
#[derive(Clone, Debug, Default)]
pub struct UploadFileParams {
    /// name of folder
    pub path: Option<String>,
    /// id of folder
    pub folderid: Option<String>,
    /// file to uplad
    pub file: Option<serde_json::Value>,
}

/// struct for typed errors of method [`get_file_by_id`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetFileByIdError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_folder`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetFolderError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`remove_by_id`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RemoveByIdError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`remove_by_path`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RemoveByPathError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`upload_file`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UploadFileError {
    UnknownValue(serde_json::Value),
}

/// Providing fileId will return given file from fileattachments.
pub async fn get_file_by_id(
    configuration: &configuration::Configuration,
    params: GetFileByIdParams,
) -> Result<String, Error<GetFileByIdError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;
    let fileid = params.fileid;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/archive/{id}",
        local_var_configuration.base_path,
        id = crate::http::apis::urlencode(id)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = fileid {
        local_var_req_builder =
            local_var_req_builder.query(&[("fileid", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<GetFileByIdError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// If no path is provided the root will be returned.  Providing fileId will return given file from fileattachments.
pub async fn get_folder(
    configuration: &configuration::Configuration,
    params: GetFolderParams,
) -> Result<crate::http::models::FolderWrap, Error<GetFolderError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let path = params.path;
    let fileid = params.fileid;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/archive/", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = path {
        local_var_req_builder =
            local_var_req_builder.query(&[("path", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = fileid {
        local_var_req_builder =
            local_var_req_builder.query(&[("fileid", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<GetFolderError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn remove_by_id(
    configuration: &configuration::Configuration,
    params: RemoveByIdParams,
) -> Result<(), Error<RemoveByIdError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/archive/{id}",
        local_var_configuration.base_path,
        id = crate::http::apis::urlencode(id)
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
        let local_var_entity: Option<RemoveByIdError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Please note that removing a folder will also resulting in removal of all the contents within!
pub async fn remove_by_path(
    configuration: &configuration::Configuration,
    params: RemoveByPathParams,
) -> Result<(), Error<RemoveByPathError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let path = params.path;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/archive/", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::DELETE, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = path {
        local_var_req_builder =
            local_var_req_builder.query(&[("path", &local_var_str.to_string())]);
    }
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
        let local_var_entity: Option<RemoveByPathError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// If not path or folderId is provided, the file will be uploaded to the root directory.
pub async fn upload_file(
    configuration: &configuration::Configuration,
    params: UploadFileParams,
) -> Result<crate::http::models::FolderFileRowWrap, Error<UploadFileError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let path = params.path;
    let folderid = params.folderid;
    let file = params.file;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/archive/", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = path {
        local_var_req_builder =
            local_var_req_builder.query(&[("path", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = folderid {
        local_var_req_builder =
            local_var_req_builder.query(&[("folderid", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    let mut local_var_form = reqwest::multipart::Form::new();
    if let Some(local_var_param_value) = file {
        local_var_form = local_var_form.text("file", local_var_param_value.to_string());
    }
    local_var_req_builder = local_var_req_builder.multipart(local_var_form);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<UploadFileError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
