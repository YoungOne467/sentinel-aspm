import logging
from typing import Dict, Any, List, Optional
import os

logger = logging.getLogger(__name__)

class GraphDBAdapter:
    """Adapter layer to prepare and store attack paths and network topologies as nodes/edges for Neo4j."""
    
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.username = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "password")
        self.enabled = os.getenv("NEO4J_ENABLED", "false").lower() == "true"
        self._driver = None

    def connect(self):
        if not self.enabled:
            logger.info("Neo4j database integration is disabled. Running in mock-graph memory mode.")
            return
        try:
            # Lazy import neo4j to avoid requiring it in local dev unless enabled
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(self.uri, auth=(self.username, self.password))
            logger.info("Connected to Neo4j Graph Database.")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")

    def close(self):
        if self._driver:
            self._driver.close()

    def sync_topology(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        """Prepare nodes and edges and execute Cypher write queries if Neo4j is enabled."""
        if not self.enabled:
            logger.debug("Neo4j disabled. Mocking topology graph sync:")
            logger.debug(f"Nodes: {len(nodes)}, Edges: {len(edges)}")
            return
            
        cypher_query_nodes = """
        UNWIND $nodes AS node
        MERGE (n:Asset {id: node.id})
        SET n.label = node.label,
            n.type = node.type,
            n.risk_score = node.risk_score,
            n.has_alert = node.has_alert,
            n.is_new = node.is_new
        """
        
        cypher_query_edges = """
        UNWIND $edges AS edge
        MATCH (a:Asset {id: edge.source})
        MATCH (b:Asset {id: edge.target})
        MERGE (a)-[r:CONNECTED_TO]->(b)
        """
        
        try:
            with self._driver.session() as session:
                session.run(cypher_query_nodes, nodes=nodes)
                session.run(cypher_query_edges, edges=edges)
            logger.info(f"Successfully synchronized {len(nodes)} nodes and {len(edges)} edges to Neo4j.")
        except Exception as e:
            logger.error(f"Neo4j graph synchronization failed: {e}")

    def query_attack_paths(self, source_id: str, target_id: str) -> List[Dict[str, Any]]:
        """Run Cypher query to find the shortest attack paths between two nodes."""
        if not self.enabled:
            return [{"path": [source_id, "gateway-router", target_id], "weight": 2.5}]
            
        cypher_query = """
        MATCH (start:Asset {id: $source_id}), (end:Asset {id: $target_id})
        MATCH p = shortestPath((start)-[:CONNECTED_TO*]->(end))
        RETURN nodes(p) AS path, length(p) AS length
        """
        try:
            with self._driver.session() as session:
                result = session.run(cypher_query, source_id=source_id, target_id=target_id)
                return [{"path": [node["id"] for node in record["path"]], "weight": record["length"]} for record in result]
        except Exception as e:
            logger.error(f"Failed to query attack paths: {e}")
            return []

# Singleton graph adapter
graph_db_adapter = GraphDBAdapter()
graph_db_adapter.connect()
