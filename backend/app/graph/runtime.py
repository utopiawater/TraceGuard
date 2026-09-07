from pathlib import Path
from typing import Any, Dict, Optional

from app.entities import GraphProjectionBatch

from .memory import InMemoryGraphProjector
from .neo4j import Neo4jProjector


class RuntimeGraphProjector:
    """Keeps the API slice available while projecting the same facts to Neo4j when online."""

    def __init__(self, uri: str, user: str, password: str, enabled: bool = True, schema_path: Optional[Path] = None) -> None:
        self.memory = InMemoryGraphProjector()
        self.entities = self.memory.entities
        self.relations = self.memory.relations
        self.uri, self.user, self.password = uri, user, password
        self.enabled = enabled
        self.schema_path = schema_path
        self.neo4j: Optional[Neo4jProjector] = None
        self.driver: Any = None
        self._status: Dict[str, Any] = {"configured": enabled, "connected": False, "uri": uri, "error": None}
        if enabled:
            self.connect()

    def connect(self) -> bool:
        if self.neo4j:
            return True
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password), connection_timeout=2)
            self.driver.verify_connectivity()
            self.neo4j = Neo4jProjector(self.driver)
            if self.schema_path and self.schema_path.exists():
                self.neo4j.apply_schema(self.schema_path)
            self._status.update({"connected": True, "error": None})
            return True
        except Exception as exc:
            if self.driver:
                self.driver.close()
            self.driver = None
            self.neo4j = None
            self._status.update({"connected": False, "error": "%s: %s" % (type(exc).__name__, exc)})
            return False

    def project(self, batch: GraphProjectionBatch) -> int:
        count = self.memory.project(batch)
        if self.enabled and (self.neo4j or self.connect()):
            try:
                self.neo4j.project(batch)
            except Exception as exc:
                self._status.update({"connected": False, "error": "%s: %s" % (type(exc).__name__, exc)})
                if self.driver:
                    self.driver.close()
                self.driver = None
                self.neo4j = None
        return count

    def status(self) -> Dict[str, Any]:
        return dict(self._status)

    def close(self) -> None:
        if self.driver:
            self.driver.close()
