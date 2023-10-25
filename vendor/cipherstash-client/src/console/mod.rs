//! Internal module for interacting with the CipherStash Console API.

use miette::Diagnostic;
use std::io::BufRead;
use std::io::Write;

use std::path::Path;

use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::config::idp_config::IdpConfig;
use crate::{
    config::{
        console_config::ConsoleConfig,
        errors::ConfigError,
        vitur_config::ViturConfig,
        workspace::{get_default_workspace, set_default_workspace},
    },
    credentials::{console_credentials::ConsoleToken, ClearTokenError, Credentials, GetTokenError},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: String,
    pub name: String,
}

#[derive(Diagnostic, Error, Debug)]
pub enum ListWorkspaceError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Credentials(#[from] GetTokenError),
}

pub struct Console<C: Credentials<Token = ConsoleToken>> {
    pub base_url: Url,
    pub credentials: C,
}

impl<C: Credentials<Token = ConsoleToken>> Console<C> {
    pub fn new(base_url: &Url, credentials: C) -> Self {
        Self {
            base_url: base_url.to_owned(),
            credentials,
        }
    }

    pub async fn list_workspaces(&self) -> Result<Vec<Workspace>, ListWorkspaceError> {
        let client = reqwest::Client::new();
        let url = self
            .base_url
            .join("/api/meta/workspaces")
            .expect("Invalid url");
        let console_token = self.credentials.get_token().await?;

        let response = client
            .get(url)
            .header("authorization", console_token.as_header())
            .send()
            .await?
            .error_for_status()?;

        let workspaces: Vec<Workspace> = response.json().await?;
        Ok(workspaces)
    }
}

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("Config: IO error, {0}")]
    Io(#[from] std::io::Error),

    #[error("ConsoleConfig: {0}")]
    ConfigError(#[from] ConfigError),

    #[error("GetTokenError: {0}")]
    GetTokenError(#[from] GetTokenError),

    #[error("ClearTokenError: {0}")]
    ClearTokenError(#[from] ClearTokenError),

    #[error("FetchWorkspaces: {0}")]
    FetchWorkspaces(#[from] ListWorkspaceError),

    #[error("WorkspaceUnavailable: Current user has no available workspaces")]
    WorkspaceUnavailable,
}

pub async fn login() -> Result<(), LoginError> {
    let console_config = ConsoleConfig::builder().with_env().build()?;
    let idp_config = IdpConfig::builder().with_env().build()?;

    let config_dir = console_config.config_dir();
    let base_url = console_config.base_url();
    let credentials = console_config.credentials();

    println!("Logging in to console");
    credentials.clear_token().await?;
    credentials.get_token().await?;

    println!("Fetching workspaces");
    let console = Console::new(&base_url, credentials);
    let workspaces = console.list_workspaces().await?;

    let ws_selection = select_workspace(&workspaces, &config_dir, std::io::stdin().lock());

    let ws_id: String = ws_selection.unwrap();

    let vitur_config = ViturConfig::builder()
        .console_config(&console_config)
        .idp_config(&idp_config)
        .build()?;
    let vitur_credentials = vitur_config.credentials();

    println!("Logging in to Vitur Workspace ID: {}", &ws_id);
    vitur_credentials.clear_token().await?;
    vitur_credentials.get_token().await?;

    Ok(())
}

pub(crate) fn select_workspace<R: BufRead>(
    workspaces: &Vec<Workspace>,
    config_dir: &Path,
    reader: R,
) -> Result<String, LoginError> {
    if workspaces.is_empty() {
        println!("No workspace found");
        Err(LoginError::WorkspaceUnavailable)
    } else if workspaces.len() == 1 {
        let ws_id = &workspaces.first().unwrap().id;
        println!(
            "Automatically selecting the single available workspace ({})",
            &ws_id
        );
        set_default_workspace(config_dir, ws_id)?;

        Ok(ws_id.clone())
    } else {
        prompt_for_workspace(workspaces, config_dir, reader)
    }
}

fn prompt_for_workspace<R: BufRead>(
    workspaces: &Vec<Workspace>,
    config_dir: &Path,
    mut reader: R,
) -> Result<String, LoginError> {
    let mut ws_selection: Option<String> = None;
    let mut default_selection: Option<usize> = None;
    while ws_selection.is_none() {
        let default_workspace = get_default_workspace(config_dir);
        println!("You have multiple workspaces:\n");

        for (idx, ws) in workspaces.iter().enumerate() {
            print!("  {}. {} ({}", idx + 1, ws.name, ws.id);
            if let Some(id) = &default_workspace {
                if *id == ws.id {
                    default_selection = Some(idx + 1);
                    print!(", Default");
                }
            }
            println!(")");
        }

        print!("\nPlease choose the workspace ({}-{}", 1, workspaces.len());
        if let Some(num) = &default_selection {
            print!(", Default {}", num);
        }
        print!("): ");

        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        reader.read_line(&mut input).unwrap();

        let answer = input.trim();

        let default_selection_with_empty_input = if answer.is_empty() {
            // Enter pressed with no selection and default exists
            default_selection
        } else {
            None
        };

        if let Some(default_value) = default_selection_with_empty_input {
            println!("Using the default Workspace {}", default_value);
            ws_selection = Some(workspaces[default_value - 1].id.clone());
        } else {
            let parsed_answer = answer.parse::<usize>();
            ws_selection = parsed_answer.ok().and_then(|i| {
                if 0 < i && i <= workspaces.len() {
                    Some(workspaces[i - 1].id.clone())
                } else {
                    None
                }
            });
            if ws_selection.is_none() {
                println!("Invalid choice: {}", input);
            }
        }
    }
    let selection = ws_selection.unwrap();
    set_default_workspace(config_dir, &selection)?;
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn empty_workspaces() -> Vec<Workspace> {
        vec![]
    }

    fn single_workspace() -> Vec<Workspace> {
        vec![Workspace {
            id: "workspace-id".to_string(),
            name: "workspace-name".to_string(),
        }]
    }

    fn two_workspaces() -> Vec<Workspace> {
        vec![
            Workspace {
                id: "workspace-id".to_string(),
                name: "workspace-name".to_string(),
            },
            Workspace {
                id: "another-workspace-id".to_string(),
                name: "another-workspace-name".to_string(),
            },
        ]
    }

    struct TearDown {
        path: String,
    }

    // This is returned from setup so drop is called at the end of each test
    impl Drop for TearDown {
        fn drop(&mut self) {
            let _unused_result = std::fs::remove_dir_all(&self.path);
        }
    }

    fn setup(default_ws_id: &str) -> (String, TearDown) {
        let dir_name = format!("/tmp/client-test-{:?}", std::thread::current().id());
        std::fs::create_dir_all(&dir_name).expect("Failed to create test dir");
        let ws_path = format!("{}/default-workspace", dir_name);
        std::fs::write(ws_path, default_ws_id).expect("Unable to write file");
        let teardown = TearDown {
            path: dir_name.to_string(),
        };
        (dir_name, teardown)
    }

    #[test]
    fn erorr_if_no_workspace() {
        let (dir_name, _teardown) = setup("workspace-id");
        let input = b"";
        let ws_selection =
            select_workspace(&empty_workspaces(), &PathBuf::from(&dir_name), &input[..]);
        assert!(ws_selection.is_err())
    }

    #[test]
    fn auto_select_if_only_1() {
        let (dir_name, _teardown) = setup("another-workspace-id");
        let input = b"";
        let ws_selection =
            select_workspace(&single_workspace(), &PathBuf::from(&dir_name), &input[..]);
        assert!(ws_selection.is_ok());
        assert_eq!(
            get_default_workspace(&PathBuf::from(&dir_name)).unwrap(),
            "workspace-id"
        )
    }

    #[test]
    fn select_default_on_empty_input() {
        let (dir_name, _teardown) = setup("another-workspace-id");

        let input = b"\n";
        let ws_selection =
            select_workspace(&two_workspaces(), &PathBuf::from(&dir_name), &input[..]);
        assert!(ws_selection.is_ok());
        assert_eq!(
            get_default_workspace(&PathBuf::from(&dir_name)).unwrap(),
            "another-workspace-id"
        )
    }

    #[test]
    fn default_not_accepted_if_not_found() {
        let (dir_name, _teardown) = setup("non-existent-id");

        let input = b"\n2\n";
        let ws_selection =
            select_workspace(&two_workspaces(), &PathBuf::from(&dir_name), &input[..]);
        assert!(ws_selection.is_ok());
        assert_eq!(
            get_default_workspace(&PathBuf::from(&dir_name)).unwrap(),
            "another-workspace-id"
        )
    }

    #[test]
    fn does_not_accept_sequence_of_invalid_choices() {
        let (dir_name, _teardown) = setup("another-workspace-id");

        let input = b"a\n-10\n42\n1\n"; // all invalid except the last "1"
        let ws_selection =
            select_workspace(&two_workspaces(), &PathBuf::from(&dir_name), &input[..]);
        assert!(ws_selection.is_ok());
        assert_eq!(
            get_default_workspace(&PathBuf::from(&dir_name)).unwrap(),
            "workspace-id"
        )
    }
}
