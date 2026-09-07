from app.entities import GraphProjectionBatch
from app.graph import RuntimeGraphProjector


def test_runtime_graph_reports_unavailable_without_losing_memory_projection():
    projector = RuntimeGraphProjector("bolt://127.0.0.1:1", "neo4j", "invalid", enabled=True)
    assert projector.status()["configured"] is True
    assert projector.status()["connected"] is False
    assert projector.project(GraphProjectionBatch()) == 0
    assert projector.entities == {}
    projector.close()
