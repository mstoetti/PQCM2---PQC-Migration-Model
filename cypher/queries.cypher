// all nodes and edges
MATCH (n)-[r]-(m)
RETURN n, r, m;

// all direct connections to one node
MATCH (c:Container)-[:contains]-(n:Node)
WHERE c.name = 'TCU'
AND n.name = 'Secure SW Update'
MATCH (n:Node)-[r]-(m:Node)
RETURN n, r, m;

// redundant explicit dependencies
MATCH (n:Node)-[r:explicit]->(m:Node)
WHERE EXISTS {
  MATCH path = (n)-[:explicit*2..]->(m)
  WHERE NONE(rel IN relationships(path) where rel = r)
}
RETURN n, r, m;

// implicit secure access dependencies
MATCH (n:Node)-[r:secure_access]->(m:Node)
WHERE NOT EXISTS {
  MATCH (n:Node)-[:explicit*1..]->(m:Node)
}
RETURN n, r, m;

// implicit dependencies for all test functions
MATCH (n:Node)-[r:shared_keys|secure_boot|secure_access|communication_dependency|functional_dependency]->(m:Node)
WHERE NOT EXISTS {
  MATCH (n:Node)-[:explicit*1..]->(m:Node)
}
RETURN n, r, m;

// all cycles
MATCH (n:Node)
WITH collect(n) as nodes
CALL apoc.nodes.cycles(nodes)
YIELD path RETURN path;

// all cycles + connection between nodes and the three container components (ECU; TCU; Server)
MATCH (n:Node)
WITH collect(n) AS nodes
CALL apoc.nodes.cycles(nodes)
YIELD path
WITH path, nodes(path) AS cycleNodes
MATCH (m:Node)-[r]-(c:Container)
WHERE m IN cycleNodes
RETURN path, m, r, c;

// clear database
match (n)
detach delete n;
