"""
Create a database connector to run queries for different alerts.
AUTHOR: Ashwinkumar Ganesan.
"""
from SPARQLWrapper import SPARQLWrapper, JSON
from urllib.request import urlopen
from urllib.error import URLError

class DatabaseConnector():
    def __init__(self, ontology_loc):
        # Different types of queries.
        self._sparql = {
                         "query": SPARQLWrapper(ontology_loc + "/query"),
                         "update": SPARQLWrapper(ontology_loc + "/update"),
                       }

        self._sparql['query'].setReturnFormat(JSON)
        self._sparql['query'].method = 'GET'

        self._sparql['update'].setReturnFormat(JSON)
        self._sparql['update'].method = 'POST'

        self._prefix = """
            PREFIX owl: <http://www.w3.org/2002/07/owl#>
            PREFIX uco: <http://ffrdc.ebiquity.umbc.edu/ns/ontology#>
            PREFIX snort: <http://ffrdc.ebiquity.umbc.edu/ns/ontology/snort#>
            PREFIX ns:   <http://www.example.org/ns#>
            PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX apt: <http://ffrdc.ebiquity.umbc.edu/ns/ontology/apt#>
            PREFIX uco_attack: <http://ffrdc.ebiquity.umbc.edu/ns/ontology/attack#>
            PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
            PREFIX os: <http://sec.accl.umbc.edu/os/ns/ontology#>
            PREFIX os_instances: <http://sec.accl.umbc.edu/os/ns/ontology/instances#>
        """

class Antecedent(DatabaseConnector):
    """
    Class Antecedent maintains the database connector and the
    queries required to get Antecendent status.
    """
    def get_status(self, a):
        """
        get_status returns the status of antecedent.
        NOTE: The status returned is 0 or 1 where 0 means unknown
              and 1 means the length of the returned query is greater than 1.
              So its truth value is a probability.
        """
        results = None
        try:
            query_string, subject = self._get_query(a)
            self._sparql['query'].setQuery(query_string)
            results = self._sparql['query'].query().convert()
        except URLError:
            print("Unable to connect to database.")
            return None

        status = 1 if len(results["results"]["bindings"]) > 0 else 0
        return status

    def _get_query(self, a):
        """
        Generate the query string given an antecedent.
        """
        subject = Antecedent._get_variables(a)
        query_string = self._prefix +\
                       "SELECT " + subject  +" WHERE "\
                       "{ " + a + " }"

        return query_string, subject[1:] # Remove ? in subject

    @staticmethod
    def _get_variables(a):
        """
        Return the subject from the triplet in the query.
        """
        return a.split(" ")[0]
