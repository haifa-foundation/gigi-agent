#!/usr/bin/env python3
from config import UPDATE_FREQUENCY, HALSEY_API_URL
from utils import loge, logi
import time
import requests


class GigiAgent(object):

    TOGGLE = HALSEY_API_URL + "/vnet/toggle"

    def __init__(self, h1_name, h2_name) -> None:
        super().__init__()
        self.last_ids_cid = 0
        self.last_ips_cid = 0
        self.h1_history= []
        self.h1_name = h1_name
        self.h2_name = h2_name

    def iter(self):
        pass

    def start(self):
        try:
            while True:
                logi("Agent run")
                self.iter()
                time.sleep(UPDATE_FREQUENCY)
        except KeyboardInterrupt:
            loge("Quitting.")
            exit(0)

    def toggle(self, hostname):
        r = requests.get(GigiAgent.TOGGLE + "?host=" + hostname)
        r.raise_for_status()
        return 1

    def qos(self, host):
        pass

    def is_score_good(self, qos):
        pass

    def is_it_up(self, pass):
        pass


if __name__ == "__main__":
    agent = GigiAgent()
    agent.start()
