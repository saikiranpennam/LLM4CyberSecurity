from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime
from tqdm import tqdm

import os
import psycopg2
import psycopg2.extras
import json
import logging

# ── logging ────────────────────────────────────────────────────────────────────

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "ingestion.log", mode="w"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)

# ── config ─────────────────────────────────────────────────────────────────────

load_dotenv()

db_config = {
    "host":     os.getenv("DB_HOST"),
    "port":     os.getenv("DB_PORT"),
    "dbname":   os.getenv("DB_NAME"),
    "user":     os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
}

MODEL_NAME = "all-MiniLM-L6-v2"
VECTOR_DIM = 384
DATA_ROOT  = Path("data/cves")
BATCH_SIZE = 500

# ── sql ────────────────────────────────────────────────────────────────────────

CREATE_TABLE_SQL = """
    CREATE EXTENSION IF NOT EXISTS vector;

    CREATE TABLE IF NOT EXISTS cves (
        id               TEXT PRIMARY KEY,
        year             INTEGER,
        state            TEXT,
        assigner         TEXT,
        description      TEXT,
        embedding        VECTOR(384),
        affected         JSONB,
        refs             JSONB,
        problem_types    JSONB,
        published        TIMESTAMP,
        last_modified    TIMESTAMP,
        reserved         TIMESTAMP,
        json_data        JSONB
    );
"""

UPSERT_SQL = """
    INSERT INTO cves (
        id, year, state, assigner, description, embedding,
        affected, refs, problem_types,
        published, last_modified, reserved, json_data
    )
    VALUES (%s, %s, %s, %s, %s, %s::vector, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s, %s, %s::jsonb)
    ON CONFLICT (id) DO UPDATE SET
        year          = EXCLUDED.year,
        state         = EXCLUDED.state,
        assigner      = EXCLUDED.assigner,
        description   = EXCLUDED.description,
        embedding     = EXCLUDED.embedding,
        affected      = EXCLUDED.affected,
        refs          = EXCLUDED.refs,
        problem_types = EXCLUDED.problem_types,
        published     = EXCLUDED.published,
        last_modified = EXCLUDED.last_modified,
        reserved      = EXCLUDED.reserved,
        json_data     = EXCLUDED.json_data
"""

# ── helpers ────────────────────────────────────────────────────────────────────

def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    logger.warning(f"Could not parse timestamp: {value}")
    return None


def detect_format(data: dict) -> str:
    """Returns '5.1' for new format, '4.0' for legacy format."""
    if "cveMetadata" in data:
        return "5.1"
    return "4.0"


def parse_cve(data: dict) -> dict | None:
    """
    Normalizes both CVE 4.0 and 5.1 formats into a flat dict.
    Returns None if the record should be skipped.
    """
    fmt = detect_format(data)

    try:
        if fmt == "5.1":
            meta = data["cveMetadata"]
            cna  = data["containers"]["cna"]

            cve_id        = meta["cveId"]
            state         = meta.get("state")
            assigner      = meta.get("assignerShortName")
            published     = parse_timestamp(meta.get("datePublished"))
            last_modified = parse_timestamp(meta.get("dateUpdated"))
            reserved      = parse_timestamp(meta.get("dateReserved"))

            descriptions  = cna.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            affected      = cna.get("affected", [])
            references    = cna.get("references", [])
            problem_types = cna.get("problemTypes", [])

        else:  # 4.0
            cve_meta      = data["cve"]["CVE_data_meta"]
            cve_id        = cve_meta["ID"]
            state         = cve_meta.get("STATE")
            assigner      = cve_meta.get("ASSIGNER")
            published     = parse_timestamp(data.get("publishedDate"))
            last_modified = parse_timestamp(data.get("lastModifiedDate"))
            reserved      = None

            desc_data = data["cve"]["description"]["description_data"]
            desc = next((d["value"] for d in desc_data if d.get("lang") == "eng"), "")

            affected      = data.get("cve", {}).get("affects", {}).get("vendor", {}).get("vendor_data", [])
            references    = data.get("cve", {}).get("references", {}).get("reference_data", [])
            problem_types = data.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])

        # skip empty descriptions and rejected CVEs
        if not desc.strip() or state == "REJECTED":
            return None

        return {
            "cve_id":        cve_id,
            "year":          int(cve_id.split("-")[1]),
            "state":         state,
            "assigner":      assigner,
            "desc":          desc,
            "affected":      affected,
            "references":    references,
            "problem_types": problem_types,
            "published":     published,
            "last_modified": last_modified,
            "reserved":      reserved,
        }

    except (KeyError, IndexError, ValueError):
        return None  # caller will log the error


def ensure_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(CREATE_TABLE_SQL)
        conn.commit()
    logger.info("Table ready.")


def flush_batch(cur, conn, batch: list) -> None:
    psycopg2.extras.execute_batch(cur, UPSERT_SQL, batch, page_size=BATCH_SIZE)
    conn.commit()
    logger.info(f"Flushed batch of {len(batch)} records.")


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    logger.info("Loading model...")
    model = SentenceTransformer(MODEL_NAME, token=False)

    all_files = list(DATA_ROOT.rglob("*.json"))
    logger.info(f"Found {len(all_files)} CVE files across {len(list(DATA_ROOT.glob('*')))} year folders.")

    conn = psycopg2.connect(**db_config)
    try:
        ensure_table(conn)

        with conn.cursor() as cur:
            batch = []

            for file_path in tqdm(all_files, desc="Processing CVEs"):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    record = parse_cve(data)
                    if record is None:
                        continue

                    embedding = model.encode(record["desc"], normalize_embeddings=True).tolist()

                    batch.append((
                        record["cve_id"],
                        record["year"],
                        record["state"],
                        record["assigner"],
                        record["desc"],
                        str(embedding),
                        json.dumps(record["affected"]),
                        json.dumps(record["references"]),
                        json.dumps(record["problem_types"]),
                        record["published"],
                        record["last_modified"],
                        record["reserved"],
                        json.dumps(data),
                    ))

                    if len(batch) >= BATCH_SIZE:
                        flush_batch(cur, conn, batch)
                        batch = []

                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")

            if batch:
                flush_batch(cur, conn, batch)

    finally:
        conn.close()

    logger.info("Ingestion finished.")


if __name__ == "__main__":
    main()