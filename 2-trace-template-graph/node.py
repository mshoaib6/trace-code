# This class defines nodes in the provenance and query graphs.
# ID: unique identifier of the node
# Type: type of node (file, process, etc.)
# Label: identifying information about the node (file name, process name, etc.)

class Node:
    def __init__(self, id, type, label):
        self.id = id
        self.type = type
        self.label = label