conn = db.getMongo()
db = conn.getDB("test");

// Collections: connectors, groups, networks, users, resources, policies 
db.runCommand ( { collMod: "connectors", changeStreamPreAndPostImages: { enabled: true } } );
db.runCommand ( { collMod: "groups", changeStreamPreAndPostImages: { enabled: true } } );
db.runCommand ( { collMod: "networks", changeStreamPreAndPostImages: { enabled: true } } );
db.runCommand ( { collMod: "users", changeStreamPreAndPostImages: { enabled: true } } );
db.runCommand ( { collMod: "resources", changeStreamPreAndPostImages: { enabled: true } } );
db.runCommand ( { collMod: "policies", changeStreamPreAndPostImages: { enabled: true } } );
