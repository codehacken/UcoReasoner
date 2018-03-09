#!/usr/bin/env python

"""
A probabilistic reasoner to reason over triples generated from a combination
of various sensors and the Unified Cybersecurity Ontology.

Ontology modified from:
Source: https://github.com/Ebiquity/Unified-Cybersecurity-Ontology
"""
__author__ = 'Ashwinkumar Ganesan'
__email__ = 'gashwin1@umbc.edu'
__date__ = '2017-03-06'

import imp
import click
import time
from lib.database import Antecedent
from lib.menu import reasoner_menu
from lib.model import BayesNetwork
from lib.writer import AntecStatusWriter

args = reasoner_menu()
defaults = imp.load_source('defaults', args['config'])
from defaults import IP_ADDRESS, PORT_NUM, ONTOLOGY_NAME, ONTOLOGY_LOC
from defaults import NULL, UCO_NAMESPACE, APT_NAMESPACE, SNORT_NAMESPACE
from defaults import OS_NAMESPACE, BRO_NAMESPACE, ATTACK_NAMESPACE
from defaults import SLEEP_TIME
from defaults import A, C, RULES, AMAP

# Menu.
OS_CHOICES = ['WINDOWS', 'UNIX']
@click.command()
@click.option('--os', type=click.Choice(OS_CHOICES), default='UNIX')
@click.option('--ip', type=str, default='10.0.2.15')
def monitor(os, ip):
    interface = Antecedent(ONTOLOGY_LOC)
    model = BayesNetwork(A, C, RULES, AMAP)
    status_writer = AntecStatusWriter(os, ip, ATTACK_NAMESPACE, ONTOLOGY_LOC)

    # Monitor in a loop.
    while(True):
        # Get the status of each antecdent.
        status = {}
        for a in A:
            status[a] = interface.get_status(A[a])

        results = model.predict(status)
        output = "Predicted Antecedents:"
        for antec in results:
            if (results[antec] > 0.0):
                output += " {}: {}".format(antec, results[antec])
        print(output)
        status_writer.toRDF(results)

        # Stop polling.
        time.sleep(SLEEP_TIME)

# Main.
if __name__ == '__main__':
    monitor()
