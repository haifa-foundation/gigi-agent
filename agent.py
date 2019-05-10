#!/usr/bin/env python3
import abc
import json
import re
from math import sqrt

from config import UPDATE_FREQUENCY, HALSEY_API_URL
from utils import loge, logi
import time
import requests


class GigiAgent(object):

    TOGGLE = HALSEY_API_URL + "/vnet/toggle"
    STATS = HALSEY_API_URL + "/sim/attack"
    QOS = HALSEY_API_URL + "/sim/qos"
    HIST = HALSEY_API_URL + "/ids/hist"

    IDS_DELTA_THRESHOLD = 1
    QOS_THRESHOLD = 0.0

    def __init__(self, h1_ip, h2_ip):
        super().__init__()
        self.last_ids_cid = 0
        self.last_ips_cid = 0
        self.h1_history = []
        self.h2_history = []
        self.h1_ip = h1_ip
        self.h2_ip = h2_ip

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

    def _fetch_hist(self, net):
        r = requests.get(GigiAgent.HIST + "?net=" + net)
        r.raise_for_status()
        return json.loads(r.text)

    def _fetch_qos(self):
        r = requests.get(GigiAgent.QOS)
        r.raise_for_status()
        return json.loads(r.text)

    @property
    def _h1_ip(self):
        return self.h1_ip

    @property
    def _h2_ip(self):
        return self.h2_ip

    def _is_hist_down(self, hist):
        if len(hist) == 0:
            return True
        avg = lambda l: sum(l)/len(l)
        sd = lambda l: sqrt(avg([x**2 for x in l]) - avg(l)**2)
        return (hist[-1] - avg(hist)) / sd(hist) < GigiAgent.IDS_DELTA_THRESHOLD

    def _qos_index(self, info_dict):
        return float(info_dict["insight"])

    def is_qos_good(self, qos):
        return qos >= GigiAgent.QOS_THRESHOLD

    def _fetch_attack_stats(self):
        """
        Cycles through hosts and If the host is an attacker instance
        or what we call a malicious host then it reports back on the
        failures/successes of the attack or in other words if the
        attack is being suppressed in anyway.
        """
        r = requests.get(GigiAgent.STATS)
        r.raise_for_status()
        return json.loads(r.text)

    def toggle(self, hostmac):
        """
        Moves a host from low security to high security
        and vice versa
        """
        r = requests.get(GigiAgent.TOGGLE + "?host=" + hostmac)
        r.raise_for_status()
        return 1

    def _get_ids_ips_occurrences(self, net):
        """
        Reads IPS alerts/logs from a SQL DB running connected in real time
        to the logs from the IPS deployed on the VN Benign
        Return 0 if up for h1 and h2
        Return 1 if up for h1 and down for h2
        Return 2 if down for h1 and up for h2
        Return 3 if down  for h1 and h2
        """
        hist = self._fetch_hist(net)
        h1_hist = [d["frequency"] for d in hist if self.h1_ip in d.values()]
        h2_hist = [d["frequency"] for d in hist if self.h2_ip in d.values()]
        return int(self._is_hist_down(h1_hist)) * 1 + \
               int(self._is_hist_down(h2_hist) * 2)

    def get_ids_ips_occurrences(self):
        return self._get_ids_ips_occurrences("ids"), self._get_ids_ips_occurrences("ips")

    def get_reward(self):
        """
        Reads QOS metrics for hosts and returns a score
        Gives a score [-1,+1] that shows better score
        for better QOS on h2 (benging) and worse on h1 (malicious)
            # 1 for h2 QOS good and h1 QOS bad
            # -0.3 for QOS bad for both or QOS good for both
            #-1 for h1 QOS good and h2 QOS bad
        """
        qos_data = self._fetch_qos()
        attack_data = self._fetch_attack_stats()

        avg = lambda l: sum(l) / len(l)
        nw_score = lambda l: avg([self._qos_index(d) for d in l])

        failrate = lambda stat: re.match(r"failure rate\s*=\s*(.+)f\s*,", stat).group(1).replace(",", ".")
        attack_score = avg([float(failrate(d["stats"])) for d in attack_data])

        scale = lambda x: -1 + 1.3 * (x+1)

        return scale(nw_score(qos_data["benign"]) - nw_score(qos_data["malicious"]) + 1.6 * attack_score)


if __name__ == "__main__":
    agent = GigiAgent(None, None)
    print(agent.toggle("bella-h1"))
