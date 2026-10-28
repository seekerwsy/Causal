import os


def pytest_addoption(parser):
    parser.addoption('--rscript', default=os.environ.get('RSCRIPT', 'Rscript'))
