"""
Implement the model to predict most-likely antecedents given a set of
partially observed rules.
"""

import numpy as np
from sklearn.naive_bayes import BernoulliNB


class BayesNetwork(object):
    """
    Construct a naive bayes model for each for the antecedents.
    """
    def __init__(self, A, C, rules):
        self._A = A
        self._num_antecs = len(self._A)
        self._rev_A = {}

        # Construct the reverse index for the antecedent list.
        for idx, antec in enumerate(self._A):
            self._rev_A[antec] = idx

        # Construct the reverse index for the consequent list.
        self._C = C
        self._rev_C = {}
        for idx, con in enumerate(self._C):
            self._rev_C[con] = idx

        self._rules = rules
        # Features the rules and convert them to a matrix.
        # NOTE: RULES - 0th position is a list of antecedents.
        #               1st position is a consequent.
        self._train_rules = []
        for rule in self._rules:
            binary_rule = [0 for i in range(0, self._num_antecs)]
            for antec in self._rules[rule][0]:
                binary_rule[self._rev_A[antec]] = 1

            self._train_rules.append(binary_rule)

        self._train_rules = np.array(self._train_rules)

        # Build the Model.
        self._model = {}
        for antec in self._A:
            clf = BernoulliNB()
            column_id = self._rev_A[antec]
            clf.fit(np.delete(self._train_rules, column_id, axis=1),
                    self._train_rules[:, column_id])
            self._model[antec] = clf

    def predict(self, status):
        """
        Predict the probability of each antecedent given a set of observations.
        """
        x = [0 for i in range(0, self._num_antecs)]
        for a in status:
            x[self._rev_A[a]] = status[a]
        x = np.array(x).reshape(1, -1)

        results = {}
        for antec in self._model:
            column_id = self._rev_A[antec]
            if(x[:, column_id] == 0):
                new_x = np.delete(x, column_id, axis=1)
                results[antec] = float(self._model[antec].predict(new_x)[0])

        return results
