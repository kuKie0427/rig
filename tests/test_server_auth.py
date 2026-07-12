"""
Simple authentication tests for rig-server.

Tests bearer token authentication on API endpoints.
"""

import os

import pytest

pytest.importorskip(
    "flask", reason="flask not installed, install server extras (-E server)"
)


@pytest.fixture
def auth_token():
    """Set up auth token for tests."""
    import rig.server.auth

    # Save original state
    original_token = rig.server.auth._server_token
    original_auth_enabled = rig.server.auth._auth_enabled

    token = "test-token-12345"
    os.environ["RIG_SERVER_TOKEN"] = token
    rig.server.auth._server_token = None  # Force regeneration

    # Enable auth for tests (simulate network binding)
    rig.server.auth.init_auth("0.0.0.0")

    yield token

    # Cleanup
    os.environ.pop("RIG_SERVER_TOKEN", None)
    rig.server.auth._server_token = original_token
    rig.server.auth._auth_enabled = original_auth_enabled


def test_auth_success(auth_token):
    """Test successful authentication with valid token."""
    from flask import Flask

    from rig.server.auth import require_auth

    app = Flask(__name__)

    @app.route("/test")
    @require_auth
    def protected_endpoint():
        return {"success": True}

    with app.test_client() as client:
        response = client.get(
            "/test", headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert response.json is not None
        assert response.json["success"] is True


def test_auth_missing_token(auth_token):
    """Test authentication failure when request is missing token.

    Server has a token configured, but the request doesn't include it.
    """
    from flask import Flask

    from rig.server.auth import require_auth

    app = Flask(__name__)

    @app.route("/test")
    @require_auth
    def protected_endpoint():
        return {"success": True}

    with app.test_client() as client:
        response = client.get("/test")  # No Authorization header
        assert response.status_code == 401
        assert response.json is not None
        assert "error" in response.json


def test_auth_invalid_token(auth_token):
    """Test authentication failure with invalid token."""
    from flask import Flask

    from rig.server.auth import require_auth

    app = Flask(__name__)

    @app.route("/test")
    @require_auth
    def protected_endpoint():
        return {"success": True}

    with app.test_client() as client:
        response = client.get("/test", headers={"Authorization": "Bearer wrong-token"})
        assert response.status_code == 401
        assert response.json is not None
        assert "error" in response.json


def test_auth_disabled_via_env():
    """Test that authentication can be disabled via RIG_DISABLE_AUTH."""
    from flask import Flask

    import rig.server.auth

    # Save original state
    original_auth_enabled = rig.server.auth._auth_enabled
    original_env = os.environ.get("RIG_DISABLE_AUTH")

    try:
        # Set environment variable to disable auth
        os.environ["RIG_DISABLE_AUTH"] = "true"

        # Re-initialize auth with network binding (would normally enable auth)
        rig.server.auth._auth_enabled = True  # Reset state
        rig.server.auth.init_auth("0.0.0.0", display=False)

        app = Flask(__name__)

        @app.route("/test")
        @rig.server.auth.require_auth
        def protected_endpoint():
            return {"success": True}

        with app.test_client() as client:
            # Should succeed without token since auth is disabled
            response = client.get("/test")
            assert response.status_code == 200
            assert response.json is not None
            assert response.json["success"] is True

    finally:
        # Cleanup
        if original_env is not None:
            os.environ["RIG_DISABLE_AUTH"] = original_env
        else:
            os.environ.pop("RIG_DISABLE_AUTH", None)
        rig.server.auth._auth_enabled = original_auth_enabled
