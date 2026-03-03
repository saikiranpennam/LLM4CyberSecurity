from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
from openai import OpenAI
from make_embeddings import MODEL_NAME, db_config

import os
import psycopg2
import ollama

load_dotenv()

db_config = {
    "host":     os.getenv("DB_HOST"),
    "port":     os.getenv("DB_PORT"),
    "dbname":   os.getenv("DB_NAME"),
    "user":     os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
}

# model = SentenceTransformer("all-miniLM-L6-v2")

_model = SentenceTransformer(MODEL_NAME)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
_conn = psycopg2.connect(**db_config)

def retrieve(query: str, top_k: int = 5) -> list[dict]:

    embedding = _model.encode(query, normalize_embeddings=True).tolist()

    with _conn.cursor() as cur:
        cur.execute("SET ivfflat.probes = 23;")
        cur.execute("""
            SELECT id, year, description, assigner, published,
                    1 - (embedding <=> %s::vector) AS similarity
            FROM cves
            ORDER BY embedding <=> %s::vector      -- cosine distance
            LIMIT %s
        """, (str(embedding), str(embedding), top_k))

        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        return  [dict(zip(columns, row)) for row in rows]


def build_prompt(query: str, results: list[dict]) -> str:
    context = "\n\n".join([
        f"CVE ID: {r['id']}\n"
        f"Published: {r['published']}\n"
        f"Assigner: {r['assigner']}\n"
        f"Description: {r['description']}"
        for r in results
    ])

    return f"""You are a cyber security assistant.

    CVE RECORDS:
    {context}

    QUESTION:
    {query}

    INSTRUCTIONS: 
    - List ALL {len(results)} CVE records above that are relevant to the question
    - For each one, state the CVE ID, published date, and a brief summary
    - If none are relevant, say so — do not make anything up.

    ANSWER:"""


def rag(query: str) -> str:
    results = retrieve(query, top_k=5)
    prompt = build_prompt(query, results)

    # response = client.chat.completions.create(
    #     model="gpt-4.1-nano",
    #     messages=[
    #         {"role": "system", "content": "You are a cybersecurity assistant."},
    #         {"role": "user", "content": prompt}
    #     ],
    #     max_tokens=1024,
    # )
    # return str(response.choices[0].message.content)

    response = ollama.chat(
        model="llama3:8b",
        messages=[
            {"role": "system", "content": "You are a cybersecurity assitant."},
            {"role": "user", "content": prompt}
        ]
    )
    return response['message']['content']

if __name__=="__main__":
    answer = rag("Are there any CVEs related to Oracle default passwords?")
    print(answer)