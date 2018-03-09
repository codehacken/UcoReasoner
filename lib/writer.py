"""
RDF Writer for reasoner.
"""
__author__ = 'Ashwinkumar Ganesan'
__email__ = 'gashwin1@umbc.edu'
__date__ = '2017-03-06'

import json
import csv
import rdflib
import datetime
from rdflib.namespace import OWL, RDF, RDFS, XSD
from rdflib import Graph, Literal, Namespace, URIRef
from .database import Log


class AntecStatusWriter():
    """
    Write the status of each the antecedents predicted.
    """
    def __init__(self, os, ip_address, ATTACK_NAMESPACE, ONTOLOGY_LOC):
        """
        Global Configuration for mapping the Antecedents to UCO.
        """
        self._attack_ns = Namespace(ATTACK_NAMESPACE + "#")
        self._attack_ns_instance = Namespace(ATTACK_NAMESPACE + "#")
        self._ontology_loc = ONTOLOGY_LOC

    def toRDF(self, status, filetype="JENA"):
        if(filetype == "JENA"):
            j_log = Log(self._ontology_loc)

        # Create a RDF Graph to write.
        g = Graph()
        for antec in status:
            # Add the Machine.
            antec_event = self._attack_ns_instance["ANT_" + antec.replace(" ", "_")]

            # Register the antecdent.
            g.add((antec_event, RDF.type, OWL.NamedIndividual))

            if (status[antec] > 0.0):
                g.add((antec_event, self._attack_ns.hasPredictedStatus,
                       Literal(True, datatype=XSD.boolean)))
            else:
                g.add((antec_event, self._attack_ns.hasPredictedStatus,
                       Literal(False, datatype=XSD.boolean)))
            # Literal('1', datatype=XSD.float) (probability)

        if(filetype == "JENA"):
            j_log.insert(g.serialize(format='nt'))
