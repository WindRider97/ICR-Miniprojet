import os
import os
from datetime import datetime

def display_tree(startpath, prefix=''):
    for item in os.listdir(startpath):
        path = os.path.join(startpath, item)
        if os.path.isdir(path):
            print(prefix + '├── ' + item)
            display_tree(path, prefix + '│   ')
        else:
            modified_time = os.path.getmtime(path)
            formatted_time = datetime.fromtimestamp(modified_time).strftime('%Y-%m-%d %H:%M:%S.%f')
            print(prefix + '├── ' + item + ' (Last Modified: ' + formatted_time + ')')
