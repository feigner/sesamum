from setuptools import setup

setup(
    name='sesamum',
    version='0.2',
    py_modules=['sesamum'],
    install_requires=[
        'click==6.6',
        'boto==2.39.0',
    ],
    entry_points='''
        [console_scripts]
        sesamum=sesamum:main
    ''',
)
