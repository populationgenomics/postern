from postern import Sandbox, SandboxProfile


def test_auto_workspace_created_and_removed():
    sandbox = Sandbox()
    workspace = sandbox.workspace
    assert workspace.is_dir()
    sandbox.close()
    assert not workspace.exists()  # Sandbox-owned temp dir is cleaned up


def test_explicit_workspace_is_kept(tmp_path):
    ws = tmp_path / 'ws'
    sandbox = Sandbox(SandboxProfile(workspace=ws))
    assert sandbox.workspace == ws
    assert ws.is_dir()
    sandbox.close()
    assert ws.exists()  # caller-owned, not removed


def test_context_manager_cleans_up():
    with Sandbox() as sandbox:
        workspace = sandbox.workspace
        assert workspace.is_dir()
    assert not workspace.exists()
