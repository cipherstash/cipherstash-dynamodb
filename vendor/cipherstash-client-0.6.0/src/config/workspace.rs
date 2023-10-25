use std::path::Path;

pub fn get_default_workspace(config_dir: &Path) -> Option<String> {
    let default_ws_path = config_dir.join("default-workspace");
    std::fs::read_to_string(default_ws_path)
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn set_default_workspace(config_dir: &Path, workspace_id: &str) -> Result<(), std::io::Error> {
    let default_ws_path = config_dir.join("default-workspace");
    std::fs::write(default_ws_path, workspace_id)
}

pub fn resolve_workspace(config_dir: &Path, workspace_id: &Option<String>) -> Option<String> {
    if let Some(ws_id) = workspace_id {
        return Some(ws_id.to_string());
    }

    if let Some(ws_id) = get_default_workspace(config_dir) {
        return Some(ws_id);
    }

    None
}
