
import io
import sqlite3

import pytest

import app as trustvault


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Use an isolated database and upload folder for each test."""
    test_db = tmp_path / "test_trustvault.db"
    test_uploads = tmp_path / "private_uploads"
    test_uploads.mkdir()

    monkeypatch.setattr(trustvault, "DB_PATH", test_db)
    monkeypatch.setattr(trustvault, "UPLOAD_DIR", test_uploads)
    trustvault.app.config.update(
        TESTING=True,
        SECRET_KEY="test-only-secret-key",
        UPLOAD_FOLDER=str(test_uploads),
    )

    trustvault.init_db()

    with trustvault.db() as con:
        users = [
            ("Owner One", "owner1@example.com", "owner"),
            ("Viewer One", "viewer1@example.com", "viewer"),
            ("Owner Two", "owner2@example.com", "owner"),
            ("Administrator", "admin@example.com", "admin"),
        ]

        for name, email, role in users:
            con.execute(
                """INSERT INTO users
                   (name, email, password_hash, role, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    name,
                    email,
                    trustvault.generate_password_hash("TestPassword123!"),
                    role,
                    trustvault.now(),
                ),
            )

        owner_id = con.execute(
            "SELECT id FROM users WHERE email=?",
            ("owner1@example.com",),
        ).fetchone()["id"]

        con.execute(
            """INSERT INTO documents
               (owner_id, title, stored_name, original_name,
                category, description, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                owner_id,
                "Private Test Document",
                "private_test.txt",
                "private_test.txt",
                "General",
                "Test-only document",
                trustvault.now(),
            ),
        )

    (test_uploads / "private_test.txt").write_text(
        "TEST DOCUMENT CONTENT",
        encoding="utf-8",
    )

    with trustvault.app.test_client() as test_client:
        yield test_client


def login(client, email):
    response = client.post(
        "/login",
        data={"email": email, "password": "TestPassword123!"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def document_id():
    with trustvault.db() as con:
        row = con.execute(
            "SELECT id FROM documents WHERE title=?",
            ("Private Test Document",),
        ).fetchone()
    return row["id"]


def test_unauthenticated_user_cannot_download(client):
    response = client.get(
        f"/documents/{document_id()}/download",
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_another_owner_cannot_download_private_document(client):
    login(client, "owner2@example.com")

    response = client.get(
        f"/documents/{document_id()}/download"
    )

    assert response.status_code == 404


def test_another_owner_cannot_delete_private_document(client):
    login(client, "owner2@example.com")

    response = client.post(
        f"/documents/{document_id()}/delete"
    )

    assert response.status_code == 403

    with trustvault.db() as con:
        doc = con.execute(
            "SELECT id FROM documents WHERE title=?",
            ("Private Test Document",),
        ).fetchone()

    assert doc is not None


def test_another_owner_cannot_manage_sharing(client):
    login(client, "owner2@example.com")

    response = client.get(
        f"/documents/{document_id()}/share"
    )

    assert response.status_code == 403


def test_grant_and_revocation_control_download(client):
    doc_id = document_id()

    login(client, "owner1@example.com")
    response = client.post(
        f"/documents/{doc_id}/share",
        data={
            "action": "grant",
            "email": "viewer1@example.com",
            "permission": "read",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    # Log out the owner and log in as the viewer.
    client.post("/logout")

    login(client, "viewer1@example.com")
    response = client.get(f"/documents/{doc_id}/download")
    assert response.status_code == 200
    assert response.data == b"TEST DOCUMENT CONTENT"

    # Revoke access as the owner.
    client.post("/logout")
    login(client, "owner1@example.com")

    response = client.post(
        f"/documents/{doc_id}/share",
        data={
            "action": "revoke",
            "email": "viewer1@example.com",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    client.post("/logout")
    login(client, "viewer1@example.com")

    response = client.get(f"/documents/{doc_id}/download")
    assert response.status_code == 404


def test_viewer_cannot_delete_private_document(client):
    login(client, "viewer1@example.com")

    response = client.post(
        f"/documents/{document_id()}/delete"
    )

    assert response.status_code == 403

def test_viewer_cannot_access_upload_page(client):
    login(client, "viewer1@example.com")

    response = client.get("/upload", follow_redirects=False)

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]
