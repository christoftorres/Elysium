"""
@author: Xiao Liang Yu
"""

import argparse

class StoreKeyValuePairAction(argparse.Action):

    def __init__(self,
                 option_strings,
                 dest,
                 nargs=None,
                 const=None,
                 default=None,
                 type=None,
                 choices=None,
                 required=False,
                 help=None,
                 metavar=None):

                if type not in (None, str):
                    raise ValueError('type for StoreKeyValuePairAction must be str')
                
                super(StoreKeyValuePairAction, self).__init__(
                    option_strings=option_strings,
                    dest=dest,
                    nargs=nargs,
                    const=const,
                    default=default,
                    type=type,
                    choices=choices,
                    required=required,
                    help=help,
                    metavar=metavar)

    def __call__(self, parser, namespace, values, option_string=None):
        
        dest = getattr(namespace, self.dest)

        if dest is None:
            setattr(namespace, self.dest, {})
            dest = getattr(namespace, self.dest)
        
        for value in values:
            # Treat `=` after the first occurence part of the value
            pair = value.split('=', maxsplit=1)
            
            # if len(pair) != 2:
            #     raise ValueError('value {} for argument {} is incorrect'.format(value, self.dest))

            k, v = pair
            dest[k] = v