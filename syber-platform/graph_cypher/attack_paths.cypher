// Attack-path computation (spec §6.2). The runnable platform implements these
// identical algorithms on NetworkX in syber/graph/store.py; this file is the
// Neo4j GDS reference for the production Neo4j Enterprise deployment.

// --- project the in-memory attack graph -----------------------------------
CALL gds.graph.project(
  'attackGraph',
  ['Asset', 'CloudResource', 'Identity'],
  {
    REACHABLE_FROM: { orientation: 'NATURAL', properties: ['edge_weight'] },
    HAS_ACCESS:     { orientation: 'NATURAL', properties: ['edge_weight'] }
  }
);

// --- Dijkstra: minimum-cost single attack path ----------------------------
CALL gds.shortestPath.dijkstra.stream('attackGraph', {
  sourceNode: id(sourceNode),
  targetNode: id(targetNode),
  relationshipWeightProperty: 'edge_weight'
})
YIELD index, sourceNode, targetNode, totalCost, nodeIds, costs, path
RETURN gds.util.asNodes(nodeIds) AS pathNodes, totalCost;

// --- Yen's k-shortest paths: blast radius ---------------------------------
CALL gds.shortestPath.yens.stream('attackGraph', {
  sourceNode: id(entryNode),
  targetNode: id(ciiAsset),
  k: 5,
  relationshipWeightProperty: 'edge_weight'
})
YIELD index, sourceNode, targetNode, totalCost, nodeIds, costs
RETURN index, gds.util.asNodes(nodeIds) AS path, totalCost
ORDER BY totalCost ASC;

// --- Betweenness centrality: remediation prioritisation -------------------
CALL gds.betweenness.stream('attackGraph')
YIELD nodeId, score
WITH gds.util.asNode(nodeId) AS node, score
SET node.betweenness_score = score
RETURN node.hostname, node.ip, score
ORDER BY score DESC
LIMIT 20;
