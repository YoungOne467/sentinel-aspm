import sys
import os

# Ensure the project root and backend are on sys.path for namespace package imports
root_dir = os.path.dirname(__file__)
sys.path.insert(0, root_dir)
sys.path.insert(0, os.path.join(root_dir, "backend"))

