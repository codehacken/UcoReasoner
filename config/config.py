"""
Configuration for test runs.
"""
__author__ = 'Ashwinkumar Ganesan'
__email__ = 'gashwin1@umbc.edu'
__date__ = '2017-03-06'

# Test Details.
NAME = "uco-rules"

# Defaults.
# _IP_ADDRESS = '192.168.56.100'
IP_ADDRESS = 'localhost'
PORT_NUM = 3030
ONTOLOGY_NAME = "UnifiedCybersecurityOntology"
ONTOLOGY_LOC = "http://" + IP_ADDRESS + ":" + str(PORT_NUM) + \
               "/" + ONTOLOGY_NAME

# Namespaces.
UCO_NAMESPACE = "http://ffrdc.ebiquity.umbc.edu/uco/ns/ontology"
APT_NAMESPACE = "http://ffrdc.ebiquity.umbc.edu/uco/ns/ontology/apt"
SNORT_NAMESPACE = "http://ffrdc.ebiquity.umbc.edu/uco/ns/ontology/snort"
BRO_NAMESPACE = "http://ffrdc.ebiquity.umbc.edu/uco/ns/ontology/bro"
OS_NAMESPACE = "http://sec.accl.umbc.edu/os/ns/ontology"

# NOTE: This is temporary.
ATTACK_NAMESPACE = "http://www.accl.umbc.edu/attack"

# Reasoner configuration.
SLEEP_TIME = 1

# NOTE: Add the set of rules.
# List all the antecedents.
A = {
    "a1" : "?ob rdf:type ?cl",
    "a2" : "?cl rdfs:subClassOf ?supcl",
    "a3" : "?att rdf:type uco_attack:Attack",
    "a4" : "?tmac rdf:type uco_attack:Machine",
    "a5" : "?tmac uco_attack:hasReconAttackStage ?att",
    "a6" : "?tmac uco_attack:hasExploitAttackStage ?att",
    "a7" : "?tmac uco_attack:hasMaintainAccessAttackStage ?att",
    "a8" : "?tmac uco_attack:hasMalActivityAttackStage ?att",
    "a9" : "?tmac uco_attack:hasActivity ?act",
    "a10": "?act rdf:type uco_attack:Activity",
    "a11": "?att uco_attack:hasExploitObservable ?act",
    "a12": "?att uco_attack:hasReconObservable ?act",
    "a13": "?att uco_attack:hasMalActivityObservable ?act",
    "a14": "?gen_att rdf:type uco_attack:Attack",
    "a15": "?att uco_attack:inheritGenericAttackProperties \"true\"^^xsd:boolean",
    "a16": "?gen_att uco_attack:isGenericAttack \"true\"^^xsd:boolean",
    "a17": "?gen_att uco_attack:hasExploitObservable ?exp_act",
    "a18": "?gen_att uco_attack:hasMaintainAccessObservable ?exp_act",
    "a19": "?gen_att uco_attack:hasReconObservable ?exp_act",
    "a20": "?f rdf:type uco_attack:File",
    "a21": "?ip rdf:type uco_attack:IPAddress",
    "a22": "?f uco_attack:hasExecuted \"true\"^^xsd:boolean",
    "a23": "?f uco_attack:hasDestIPAddress ?ip",
    "a24": "?tmac uco_attack:hasIPAddress ?ip",
    "a25": "?f uco_attack:hasDownloaded \"true\"^^xsd:boolean",
    "a26": "?f uco_attack:hasExtension \"bat\"",
    "a27": "?f uco_attack:hasExtension \"exe\"",
    "a28": "?prot rdf:type uco_attack:Protocol",
    "a29": "?att uco_attack:hasSuspiciousProtocol ?prot",
    "a30": "?tmac uco_attack:hasProtocol ?prot",
}

# List of all consequents.
C = {
    "c1": "?ob rdf:type ?supcl",
    "c2": "?tmac uco_attack:underAttack ?att",
    "c3": "?tmac uco_attack:hasExploitAttackStage ?att",
    "c4": "?tmac uco_attack:hasMaintainAccessAttackStage ?att",
    "c5": "?tmac uco_attack:hasReconAttackStage ?att",
    "c6": "?tmac uco_attack:hasMalActivityAttackStage ?att",
    "c7": "?att	uco_attack:hasExploitObservable	?exp_act",
    "c8": "?att	uco_attack:hasMaintainAccessObservable ?exp_act",
    "c9": "?att uco_attack:hasReconObservable ?exp_act",
    "c10": "?att uco_attack:hasMalActivityObservable ?exp_act",
    "c11": "?tmac uco_attack:hasActivity uco_attack:SuspiciousDownloadExecute",
    "c12": "?tmac uco_attack:hasActivity uco_attack:SuspiciousDownload",
    "c13": "?tmac uco_attack:hasActivity uco_attack:SuspiciousProtocol",
}


# Encoding the rules.
RULES = {
    "r1": [['a1', 'a2'], 'c1'],
    "r2": [['a3', 'a4', 'a5', 'a6', 'a7', 'a8'], 'c2'],
    "r3": [['a3', 'a4', 'a6', 'a7', 'a8'], 'c2'],
    "r4": [['a10', 'a3', 'a4', 'a9', 'a11'], 'c3'],
    "r5": [['a10', 'a3', 'a4', 'a9', 'a11'], 'c4'],
    "r6": [['a10', 'a2', 'a9', 'a12'], 'c5'],
    "r7": [['a10', 'a4', 'a3', 'a9', 'a13'], 'c6'],
    "r8": [['a3', 'a14', 'a15', 'a16', 'a17'], 'c7'],
    "r9": [['a3', 'a14', 'a15', 'a18'], 'c8'],
    "r10": [['a3', 'a14', 'a15', 'a16', 'a19'], 'c9'],
    "r11": [['a3', 'a14', 'a15', 'a16', 'a20'],  'c10'],
    "r12": [['a4', 'a20', 'a21', 'a22', 'a23', 'a24', 'a25'], 'c11'],
    "r13": [['a20', 'a21', 'a4', 'a25', 'a26', 'a23', 'a24'], 'c12'],
    "r14": [['a20', 'a21', 'a4', 'a25', 'a27', 'a23', 'a24'], 'c12'],
    "r15": [['a28', 'a3', 'a4', 'a29', 'a30'], 'c13']
}
