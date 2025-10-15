from setuptools import setup, find_packages

setup(
    name="firman",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "angr",  
    ],
    entry_points={
        'console_scripts': [
            'yourcli = firman.firman:main',
        ],
    },
)