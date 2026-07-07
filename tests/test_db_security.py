"""Seguridad a nivel de BD: singleton del super_admin y rol de app sin DDL."""
import pytest

pytestmark = pytest.mark.db


def _insert_superadmin(cur, username):
    cur.execute("INSERT INTO pago_users (username,email,password_hash,full_name,role) "
                "VALUES (%s,%s,'x','Super Test','super_admin') RETURNING id",
                (username, f"{username}@test.local"))
    return cur.fetchone()[0]


class TestSuperadminSingleton:
    def test_no_puede_haber_dos_super_admins(self, db_conn):
        import psycopg2
        with db_conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pago_users WHERE role='super_admin'")
            existing = cur.fetchone()[0]
            if existing == 0:
                _insert_superadmin(cur, "sa_test_1")
            with pytest.raises(psycopg2.Error):
                _insert_superadmin(cur, "sa_test_2")
        db_conn.rollback()

    def test_super_admin_no_se_modifica_ni_elimina(self, db_conn):
        import psycopg2
        with db_conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pago_users WHERE role='super_admin'")
            if cur.fetchone()[0] == 0:
                _insert_superadmin(cur, "sa_test_3")
            cur.execute("SAVEPOINT sp")
            with pytest.raises(psycopg2.Error):
                cur.execute("UPDATE pago_users SET is_active=FALSE WHERE role='super_admin'")
            cur.execute("ROLLBACK TO SAVEPOINT sp")
            with pytest.raises(psycopg2.Error):
                cur.execute("DELETE FROM pago_users WHERE role='super_admin'")
        db_conn.rollback()

    def test_no_promover_a_super_admin(self, db_conn):
        import psycopg2
        with db_conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pago_users WHERE role='super_admin'")
            if cur.fetchone()[0] == 0:
                _insert_superadmin(cur, "sa_test_4")
            cur.execute("INSERT INTO pago_users (username,email,password_hash,full_name,role) "
                        "VALUES ('promo_test','promo@test.local','x','Promo','cobrador') RETURNING id")
            uid = cur.fetchone()[0]
            with pytest.raises(psycopg2.Error):
                cur.execute("UPDATE pago_users SET role='super_admin' WHERE id=%s", (uid,))
        db_conn.rollback()


class TestAppRole:
    def test_dimed_app_sin_ddl(self, db_conn):
        """El rol de la app no debe poder crear objetos en el schema."""
        with db_conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname='dimed_app'")
            if not cur.fetchone():
                pytest.skip("rol dimed_app no existe (migracion 002 no aplicada)")
            cur.execute("SELECT has_schema_privilege('dimed_app','public','CREATE')")
            assert cur.fetchone()[0] is False
            cur.execute("SELECT has_table_privilege('dimed_app','pago_users','SELECT')")
            assert cur.fetchone()[0] is True
