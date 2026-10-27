"""Remove unique constraint from purl to allow same component in multiple applications

Revision ID: 006
Revises: 005
Create Date: 2026-10-27

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade():
    # SQLite doesn't support ALTER COLUMN to remove constraints directly
    # We need to recreate the table without the unique constraint
    op.execute("""
        CREATE TABLE components_new (
            id INTEGER PRIMARY KEY,
            name VARCHAR NOT NULL,
            version VARCHAR NOT NULL,
            component_type VARCHAR NOT NULL,
            purl VARCHAR,
            supplier VARCHAR,
            description TEXT,
            license VARCHAR,
            cpe VARCHAR,
            application_id INTEGER,
            sbom_id VARCHAR,
            created_at DATETIME,
            updated_at DATETIME,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    """)
    
    # Copy data from old table to new table
    op.execute("""
        INSERT INTO components_new (id, name, version, component_type, purl, supplier, description, license, cpe, application_id, sbom_id, created_at, updated_at)
        SELECT id, name, version, component_type, purl, supplier, description, license, cpe, application_id, sbom_id, created_at, updated_at
        FROM components
    """)
    
    # Drop old table
    op.execute("DROP TABLE components")
    
    # Rename new table to old name
    op.execute("ALTER TABLE components_new RENAME TO components")
    
    # Recreate indexes
    op.execute("CREATE INDEX ix_components_name ON components (name)")
    op.execute("CREATE INDEX ix_components_version ON components (version)")
    op.execute("CREATE INDEX ix_components_purl ON components (purl)")
    op.execute("CREATE INDEX ix_components_sbom_id ON components (sbom_id)")


def downgrade():
    # Re-add the unique constraint
    op.execute("""
        CREATE TABLE components_new (
            id INTEGER PRIMARY KEY,
            name VARCHAR NOT NULL,
            version VARCHAR NOT NULL,
            component_type VARCHAR NOT NULL,
            purl VARCHAR UNIQUE,
            supplier VARCHAR,
            description TEXT,
            license VARCHAR,
            cpe VARCHAR,
            application_id INTEGER,
            sbom_id VARCHAR,
            created_at DATETIME,
            updated_at DATETIME,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    """)
    
    # Copy data
    op.execute("""
        INSERT INTO components_new (id, name, version, component_type, purl, supplier, description, license, cpe, application_id, sbom_id, created_at, updated_at)
        SELECT id, name, version, component_type, purl, supplier, description, license, cpe, application_id, sbom_id, created_at, updated_at
        FROM components
    """)
    
    # Drop old table
    op.execute("DROP TABLE components")
    
    # Rename
    op.execute("ALTER TABLE components_new RENAME TO components")
    
    # Recreate indexes
    op.execute("CREATE INDEX ix_components_name ON components (name)")
    op.execute("CREATE INDEX ix_components_version ON components (version)")
    op.execute("CREATE UNIQUE INDEX ix_components_purl ON components (purl)")
    op.execute("CREATE INDEX ix_components_sbom_id ON components (sbom_id)")
