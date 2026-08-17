import os


def service_status(service_name):
    return os.system("systemctl status " + service_name)
