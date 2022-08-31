#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='CR',
    version='0.0',
    description='',
    author='Xiao Liang <xiaoly@comp.nus.edu.sg>',
    packages=find_packages(),
    install_requires=[
        'py-solc == 3.2.0', 'Logbook == 1.4.1', 'deap == 1.3.0',
        'attrs == 18.2.0', 'docker == 3.7.2', 'numpy == 1.16.2',
        'matplotlib == 3.4.1'
    ],
    extras_require={'dev': ['pylint', 'mypy', 'yapf']},
    entry_points={
        'setuptools.installation': [
            'eggsecutable = __main__:main'
        ]
    }
)
