import os


def service_status(service_name):
    del service_name
    return os.system("systemctl is-system-running --quiet")
