use rusqlite::{Connection, Result};
use std::path::Path;

pub struct MemoryGraph {
    conn: Connection,
}

impl MemoryGraph {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        Ok(Self { conn })
    }

    /// The agent uses an SQLite self-join over its entity index rather than writing new schema edges.
    /// This read-only derivation is highly efficient and pairs perfectly with our ort and oxigraph local pipelines.
    pub fn get_derived_triples(&self, entity_id: &str) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT e1.name, e1.relation, e2.name 
             FROM entity_index e1 
             INNER JOIN entity_index e2 
             ON e1.target_id = e2.id 
             WHERE e1.source_id = ?1"
        )?;

        let triple_iter = stmt.query_map([entity_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;

        let mut triples = Vec::new();
        for triple in triple_iter {
            triples.push(triple?);
        }

        Ok(triples)
    }
}
