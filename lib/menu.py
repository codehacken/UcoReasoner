"""
Provide a set of menu options for the reasoner.
"""
__author__ = 'Ashwinkumar Ganesan'
__email__ = 'gashwin1@umbc.edu'
__date__ = '2017-03-06'

import argparse

def reasoner_menu():
    parser = argparse.ArgumentParser(description='Rules reasoner.')
    parser.add_argument('-c', '--config-file',
                        action='store', type=str,
                        default="config/config.py",
                        dest='config', help='Configuration parameters.')
    args = vars(parser.parse_args())
    return args
